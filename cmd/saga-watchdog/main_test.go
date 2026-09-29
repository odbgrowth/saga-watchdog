//go:build linux || darwin

package main

import (
 "bytes"
 "context"
 "encoding/json"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "github.com/odbgrowth/saga-watchdog/internal/config"
 "github.com/odbgrowth/saga-watchdog/internal/event"
 "github.com/odbgrowth/saga-watchdog/internal/gitinfo"
 "github.com/odbgrowth/saga-watchdog/internal/policy"
 "github.com/odbgrowth/saga-watchdog/internal/sources/socket"
 "github.com/odbgrowth/saga-watchdog/internal/store"
)

func TestCLIHelper(t *testing.T) {
 if os.Getenv("SAGA_TEST_CLI")!="1"{return}
 for i,a:=range os.Args {if a=="--"{os.Exit(cli(os.Args[i+1:]))}}
 os.Exit(99)
}

func fixture(t *testing.T,extra string) string {
 t.Helper()
 root:=t.TempDir()
 cmd:=exec.Command("git","init","-b","test/watchdog",root)
 if out,err:=cmd.CombinedOutput();err!=nil{t.Fatalf("git init: %s %v",out,err)}
 t.Setenv("SAGA_WATCHDOG_STATE_DIR",t.TempDir())
 if err:=os.WriteFile(filepath.Join(root,config.Filename),[]byte(extra),0600);err!=nil{t.Fatal(err)}
 resolved,err:=filepath.EvalSymlinks(root);if err!=nil{t.Fatal(err)}
 return resolved
}

func cliCommand(t *testing.T,root string,args ...string) (*exec.Cmd,*bytes.Buffer) {
 t.Helper()
 ctx,cancel:=context.WithTimeout(context.Background(),12*time.Second);t.Cleanup(cancel)
 argv:=append([]string{"-test.run=^TestCLIHelper$","--"},args...)
 cmd:=exec.CommandContext(ctx,os.Args[0],argv...)
 cmd.Dir=root;cmd.Env=append(os.Environ(),"SAGA_TEST_CLI=1","GORACE=atexit_sleep_ms=0")
 var out bytes.Buffer;cmd.Stdout=&out;cmd.Stderr=&out
 return cmd,&out
}

func exitCode(err error) int {
 if err==nil{return 0}
 if e,ok:=err.(*exec.ExitError);ok{return e.ExitCode()}
 return -1
}

func TestRunModesAndTimeout(t *testing.T) {
 for _,tc:=range []struct{name,mode,script string;want int}{
  {"normal","enforce","printf ok",0},
  {"nonzero","enforce","exit 7",7},
  {"tamper","enforce","printf '# changed\\n' >> .saga-watchdog.yaml; sleep 5",125},
  {"observe","observe","printf '# changed\\n' >> .saga-watchdog.yaml; sleep 0.2",0},
  {"timeout","enforce","sleep 5",125},
 } {
  t.Run(tc.name,func(t *testing.T){
   duration:="10s";if tc.name=="timeout"{duration="200ms"}
   root:=fixture(t,"version: 1\nprofile: coding-agent\nmode: "+tc.mode+"\nrun:\n  max_duration: "+duration+"\n  stop_grace_period: 50ms\n")
   cmd,out:=cliCommand(t,root,"run","--","sh","-c",tc.script)
   if got:=exitCode(cmd.Run());got!=tc.want{t.Fatalf("exit %d want %d\n%s",got,tc.want,out)}
   dir,r,err:=store.Locate(root,"");if err!=nil{t.Fatal(err)}
   if r.Finished==nil{t.Fatal("run not finalized")}
   data,err:=os.ReadFile(filepath.Join(dir,"events.jsonl"));if err!=nil{t.Fatal(err)}
   var events []event.Event
   for _,line:=range bytes.Split(bytes.TrimSpace(data),[]byte("\n")){var e event.Event;if err=json.Unmarshal(line,&e);err!=nil{t.Fatal(err)};events=append(events,e)}
   if len(events)<2{t.Fatalf("missing lifecycle events: %s",data)}
   if tc.name=="tamper"&&!strings.Contains(string(data),"policy-tamper"){t.Fatalf("tamper not audited: %s",data)}
   if tc.name=="timeout"&&r.Rule!="max-duration"{t.Fatalf("timeout reason: %+v",r)}
  })
 }
}

func TestControlsAndIntegration(t *testing.T) {
 root:=fixture(t,"version: 1\nmode: enforce\nrun:\n  max_duration: 10s\n  stop_grace_period: 50ms\nnetwork:\n  deny: [blocked.example]\n")
 cmd,out:=cliCommand(t,root,"run","--","sh","-c","sleep 8")
 if err:=cmd.Start();err!=nil{t.Fatal(err)}
 done:=make(chan error,1);go func(){done<-cmd.Wait()}()
 var r store.Run
 deadline:=time.After(5*time.Second);ticker:=time.NewTicker(20*time.Millisecond);defer ticker.Stop()
 ready:
 for {select {
 case <-deadline:t.Fatal("run did not start")
 case err:=<-done:t.Fatalf("early exit %v: %s",err,out)
 case <-ticker.C:
  _,found,err:=store.Locate(root,"");if err==nil&&found.Socket!=""{r=found;break ready}
 }}
 send:=func(op string,input socket.Input) socket.Response {
  t.Helper();path:=r.Socket;if op=="pause"||op=="resume"||op=="kill"||op=="status"{path=r.Control}
  response,err:=socket.Send(path,socket.Request{Operation:op,RunID:r.ID,Event:input})
  if err!=nil{t.Fatal(err)};return response
 }
 allowed:=send("check",socket.Input{Type:"network",Action:"connect",Target:"allowed.example"})
 if !allowed.Allowed{t.Fatalf("normal check denied: %+v",allowed)}
 denied:=send("check",socket.Input{Type:"network",Action:"connect",Target:"blocked.example"})
 if denied.Allowed||denied.Decision==nil||denied.Decision.Action!="pause"{t.Fatalf("bad denial: %+v",denied)}
 status:=send("status",socket.Input{});if status.Run==nil||status.Run.Status!="paused"{t.Fatalf("not paused: %+v",status)}
 send("resume",socket.Input{})
 status=send("status",socket.Input{});if status.Run.Status!="running"{t.Fatal("not resumed")}
 send("kill",socket.Input{})
 select{case err:=<-done:if exitCode(err)!=125{t.Fatalf("exit %v: %s",err,out)};case <-time.After(3*time.Second):t.Fatal("external kill did not stop run")}
 dir,_,err:=store.Locate(root,r.ID);if err!=nil{t.Fatal(err)}
 data,err:=os.ReadFile(filepath.Join(dir,"events.jsonl"));if err!=nil{t.Fatal(err)}
 if !strings.Contains(string(data),`"action":"resume"`){t.Fatal("resume not audited")}
}

func TestInitPreservesPolicyAndUnbornBranch(t *testing.T) {
 root:=fixture(t,config.DefaultYAML)
 info,err:=gitinfo.Inspect(root);if err!=nil{t.Fatal(err)}
 if info.Branch!="test/watchdog"{t.Fatalf("unborn branch: %s",info.Branch)}
 cmd,_:=cliCommand(t,root,"init")
 if got:=exitCode(cmd.Run());got!=2{t.Fatalf("init overwritten policy, exit %d",got)}
 data,err:=os.ReadFile(filepath.Join(root,config.Filename));if err!=nil{t.Fatal(err)}
 if string(data)!=config.DefaultYAML{t.Fatal("policy changed")}
}

func TestObserveChecksAndProtectedBranch(t *testing.T) {
 if !permits("observe",policy.Decision{Action:"kill"})||permits("enforce",policy.Decision{Action:"pause"}){t.Fatal("mode decision")}
 root:=fixture(t,config.DefaultYAML)
 if out,err:=exec.Command("git","-C",root,"branch","-m","main").CombinedOutput();err!=nil{t.Fatalf("%s %v",out,err)}
 cmd,_:=cliCommand(t,root,"run","--","sh","-c","exit 0")
 if got:=exitCode(cmd.Run());got!=2{t.Fatalf("protected branch start: %d",got)}
}

func TestChildEnvironmentUsesCurrentRun(t *testing.T) {
 root:=fixture(t,"version: 1\nmode: enforce\nrun:\n  stop_grace_period: 50ms\n")
 t.Setenv("SAGA_WATCHDOG_RUN_ID","run_stale_parent")
 t.Setenv("SAGA_WATCHDOG_SOCKET","/stale-parent/events.sock")
 script:=`printf '%s\n%s\n' "$SAGA_WATCHDOG_RUN_ID" "$SAGA_WATCHDOG_SOCKET" > inherited.txt`
 cmd,out:=cliCommand(t,root,"run","--","sh","-c",script)
 if got:=exitCode(cmd.Run());got!=0{t.Fatalf("run exit %d: %s",got,out)}
 _,r,err:=store.Locate(root,"");if err!=nil{t.Fatal(err)}
 data,err:=os.ReadFile(filepath.Join(root,"inherited.txt"));if err!=nil{t.Fatal(err)}
 if want:=r.ID+"\n"+r.Socket+"\n";string(data)!=want{t.Fatalf("child inherited %q, want %q",data,want)}
}

func TestKillCLIWithBrokenGitConfig(t *testing.T) {
 root:=fixture(t,config.DefaultYAML)
 ctx,cancel:=context.WithCancel(context.Background());defer cancel()
 calls:=make(chan socket.Call,1)
 ipc,err:=socket.Start(ctx,calls);if err!=nil{t.Fatal(err)};defer ipc.Close()
 r:=store.Run{ID:event.NewID("run"),Project:"test",Status:"paused",Socket:ipc.Events,Control:ipc.Control,Started:time.Now().UTC()}
 audit,err:=store.Create(root,r);if err!=nil{t.Fatal(err)};defer audit.Close()
 // Isolate CLI routing from the running monitor's legitimate reaction to
 // broken Git metadata, which could otherwise race this control request.
 received:=make(chan socket.Request,1)
 go func(){select{
 case call:=<-calls:
  received<-call.Request
  snapshot:=r;snapshot.Status="terminating"
  call.Reply<-socket.Response{Allowed:true,Run:&snapshot}
 case <-ctx.Done():
 }}()
 if err:=os.WriteFile(filepath.Join(root,".git","config"),[]byte("[broken\n"),0600);err!=nil{t.Fatal(err)}
 if _,err:=gitinfo.Inspect(root);err==nil{t.Fatal("fixture did not make Git inspection fail")}
 cmd,out:=cliCommand(t,root,"kill",r.ID)
 if got:=exitCode(cmd.Run());got!=0{t.Fatalf("kill exit %d: %s",got,out)}
 select{
 case request:=<-received:
  if request.Operation!="kill"||request.RunID!=r.ID{t.Fatalf("wrong control request: %+v",request)}
 case <-time.After(time.Second):t.Fatal("kill did not reach the paused run's control socket")
 }
}
