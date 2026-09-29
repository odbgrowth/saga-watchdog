// Package filesystem observes changes, not reads or pre-action authorization.
package filesystem

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/odbgrowth/saga-watchdog/internal/config"
	"github.com/odbgrowth/saga-watchdog/internal/event"
	"github.com/odbgrowth/saga-watchdog/internal/gitinfo"
	"github.com/odbgrowth/saga-watchdog/internal/policy"
)

type Source struct { watcher *fsnotify.Watcher; done chan struct{}; cancel context.CancelFunc; once sync.Once }

func relative(root,path string) (string,bool) {
	r,err:=filepath.Rel(root,path);if err!=nil||r==".."||strings.HasPrefix(r,".."+string(filepath.Separator)){return "",false};return filepath.ToSlash(r),true
}

func Start(ctx context.Context,g gitinfo.Info,c config.Config,out chan<- event.Event,fail chan<- error) (*Source,error) {
	w,err:=fsnotify.NewWatcher();if err!=nil{return nil,err}
	ctx,cancel:=context.WithCancel(ctx);s:=&Source{watcher:w,done:make(chan struct{}),cancel:cancel}
	logical:=func(path string) string {
		if r,ok:=relative(g.Root,path);ok{return r}
		if r,ok:=relative(g.GitDir,path);ok{return ".git/"+r}
		if r,ok:=relative(g.CommonDir,path);ok{return ".git/"+r}
		return ""
	}
	ignored:=func(p string) bool {
		// Never prune ancestors of explicitly protected paths, including globs.
		for _,pattern:=range c.Filesystem.Protect {
			prefix:=strings.TrimRight(strings.SplitN(pattern,"*",2)[0],"/")
			if p==prefix||strings.HasPrefix(prefix,p+"/")||policy.Match(pattern,p){return false}
		}
		return policy.Ignored(p,c.Filesystem.Ignore)
	}
	emit:=func(path,action string) bool {
		p:=logical(path);if p==""||ignored(p){return true}
		// External worktree Git directories contain indexes and locks that are
		// not project paths. Observe only their security controls here; branch
		// transitions are queried independently by the run loop.
		if _,inside:=relative(g.Root,path);!inside&&p!=".git/config"&&p!=".git/hooks"&&!strings.HasPrefix(p,".git/hooks/"){return true}
		e:=event.Event{Timestamp:time.Now().UTC(),Source:"filesystem",Type:"file",Action:action,Target:p,Result:"success"}
		select {case out<-e:return true;case <-ctx.Done():return false;case <-time.After(time.Second):select{case fail<-fmt.Errorf("filesystem event queue overflow"):default:};return false}
	}
	var addTree func(string,bool) error
	addTree=func(path string,created bool) error {
		return filepath.WalkDir(path,func(p string,d fs.DirEntry,walkErr error) error {
			if walkErr!=nil { if os.IsNotExist(walkErr){return nil};return walkErr }
			name:=logical(p);if ignored(name){if d.IsDir(){return filepath.SkipDir};return nil}
			// WalkDir does not follow symlinks. Their creation is still an event.
			if d.IsDir(){if err:=w.Add(p);err!=nil&&!os.IsNotExist(err){return err}} else if created {if !emit(p,"create"){return context.Canceled}}
			return nil
		})
	}
	if err=addTree(g.Root,false);err!=nil {cancel();w.Close();return nil,err}
	// Linked worktrees keep their Git controls outside the project tree.
	for _,dir:=range []string{g.GitDir,g.CommonDir} {
		if dir==""{continue};if _,ok:=relative(g.Root,dir);ok{continue}
		if err=w.Add(dir);err!=nil{cancel();w.Close();return nil,err}
		hooks:=filepath.Join(dir,"hooks");if _,err=os.Stat(hooks);err==nil {if err=addTree(hooks,false);err!=nil{cancel();w.Close();return nil,err}}
	}
	go func(){
		defer close(s.done)
		for {select {
		case <-ctx.Done():return
		case err,ok:=<-w.Errors:if !ok{return};select{case fail<-fmt.Errorf("filesystem observation failed: %w",err):case <-ctx.Done():};return
		case e,ok:=<-w.Events:
			if !ok{return}
			if e.Has(fsnotify.Create) {
				if info,err:=os.Lstat(e.Name);err==nil&&info.IsDir(){if err=addTree(e.Name,true);err!=nil {select{case fail<-err:case <-ctx.Done():};return}}
			}
			action:="";switch {case e.Has(fsnotify.Remove):action="delete";case e.Has(fsnotify.Rename):action="rename";case e.Has(fsnotify.Create):action="create";case e.Has(fsnotify.Write)||e.Has(fsnotify.Chmod):action="write"}
			if action!=""&&!emit(e.Name,action){return}
		}}
	}()
	return s,nil
}

func(s *Source) Close() error {var err error;s.once.Do(func(){s.cancel();err=s.watcher.Close();<-s.done});return err}
