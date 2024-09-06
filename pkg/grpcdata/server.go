package grpcdata

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net"

	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc"
	cluster_v2 "kmesh.net/kmesh/api/v2/cluster"
	core_v2 "kmesh.net/kmesh/api/v2/core"
	pb "kmesh.net/kmesh/api/v2/grpcdata"
	listener_v2 "kmesh.net/kmesh/api/v2/listener"
	route_v2 "kmesh.net/kmesh/api/v2/route"
	maps_v2 "kmesh.net/kmesh/pkg/cache/v2/maps"
)

type server struct {
	pb.KmeshMsgServiceServer
}

func handleRequest(req *pb.MsgRequest) (error, []byte) {
	var err error
	var Msg []byte
	switch req.XdsOpt.XdsNmae {
	case pb.XdsNmae_Cluster:
		valueMsg := &cluster_v2.Cluster{}
		err = proto.Unmarshal(req.Msg, valueMsg)
		if err != nil {
			return err, nil
		}
		switch req.XdsOpt.Opt {
		case pb.Opteration_UPDATE:
			err = maps_v2.ClusterUpdate(req.Key, valueMsg)
		case pb.Opteration_LOOKUP:
			err = maps_v2.ClusterLookup(req.Key, valueMsg)
		case pb.Opteration_DELETE:
			err = maps_v2.ClusterDelete(req.Key)
		}
		if err != nil {
			return err, nil
		}
		Msg, err = proto.Marshal(valueMsg)
	case pb.XdsNmae_Listener:
		decodedKeyByte, err := base64.StdEncoding.DecodeString(req.Key)
		if err != nil {
			log.Fatalf("DecodeString failed, err is: %v", err)
		}
		key := &core_v2.SocketAddress{}
		err = proto.Unmarshal(decodedKeyByte, key)
		if err != nil {
			return fmt.Errorf("unmarshal key failed :%v", err), nil
		}

		valueMsg := &listener_v2.Listener{}
		err = proto.Unmarshal(req.Msg, valueMsg)
		if err != nil {
			return fmt.Errorf("Unmarshal listener failed:%v", err), nil
		}
		log.Printf("key:%v", key)
		log.Printf("valueMsg:%v", valueMsg)
		switch req.XdsOpt.Opt {
		case pb.Opteration_UPDATE:
			err = maps_v2.ListenerUpdate(key, valueMsg)
		case pb.Opteration_LOOKUP:
			err = maps_v2.ListenerLookup(key, valueMsg)
		case pb.Opteration_DELETE:
			err = maps_v2.ListenerDelete(key)
		}
		if err != nil {
			return err, nil
		}
		log.Printf("valueMsg:%v", valueMsg)
		if valueMsg != nil {
			Msg, err = proto.Marshal(valueMsg)
		}
		if err != nil {
			return fmt.Errorf("marshal listener failed:%v", err), nil
		}
	case pb.XdsNmae_Route:
		valueMsg := &route_v2.RouteConfiguration{}
		err := proto.Unmarshal(req.Msg, valueMsg)
		if err != nil {
			return err, nil
		}
		switch req.XdsOpt.Opt {
		case pb.Opteration_UPDATE:
			err = maps_v2.RouteConfigUpdate(req.Key, valueMsg)
		case pb.Opteration_LOOKUP:
			err = maps_v2.RouteConfigLookup(req.Key, valueMsg)
		case pb.Opteration_DELETE:
			err = maps_v2.RouteConfigDelete(req.Key)
		}
		if err != nil {
			return err, nil
		}
		Msg, err = proto.Marshal(valueMsg)
	}
	return err, Msg
}

func (s *server) HandleMsg(ctx context.Context, req *pb.MsgRequest) (*pb.MsgResponse, error) {
	log.Printf("Received req.Name: %v", req.Key)
	log.Printf("Received req.XdsOpt.Opt %v req.XdsOpt.XdsNmae %v \n ", req.XdsOpt.Opt, req.XdsOpt.XdsNmae)
	//log.Printf("Received req.Msg: %v", req.Msg)

	err, Msg := handleRequest(req)
	if err != nil {
		log.Printf("err is : %v", err)
		return &pb.MsgResponse{ErrorCode: -1, Msg: Msg}, err
	}
	//log.Printf("valueMsg:\nvalueMsg.ApiStatus:%v\n valueMsg.Name:%v\nvalueMsg.LbPolicy:%v\n valueMsg.LoadAssignment:%v\n valueMsg.ConnectTimeout:%v", valueMsg.ApiStatus, valueMsg.Name, valueMsg.LbPolicy, valueMsg.LoadAssignment, valueMsg.ConnectTimeout)
	return &pb.MsgResponse{ErrorCode: 0, Msg: Msg}, err
}

func GrpcInitServer() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterKmeshMsgServiceServer(s, &server{})
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
