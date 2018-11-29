package rpc

import (
	"net/http"

	"github.com/najimmy/go-simplechain/log"

	"github.com/osamingo/jsonrpc"
)

type JsonHandler interface {
	jsonrpc.Handler
	Name() string
	Params() interface{}
	Result() interface{}
}

type RpcServer struct {
	mr *jsonrpc.MethodRepository
}

func NewRpcServer() *RpcServer {
	return &RpcServer{
		mr: jsonrpc.NewMethodRepository(),
	}
}

func (js *RpcServer) RegisterHandler(handler JsonHandler) {
	if err := js.mr.RegisterMethod(handler.Name(), handler, handler.Params, handler.Result); err != nil {
		log.CLog().Warning(err)
	}

}

func (js *RpcServer) Start() {

	http.Handle("/jrpc", js.mr)
	// http.HandleFunc("/jrpc/debug", mr.ServeDebug)
	go func() {
		if err := http.ListenAndServe(":8080", http.DefaultServeMux); err != nil {
			log.CLog().Warning(err)
		}
	}()
}
