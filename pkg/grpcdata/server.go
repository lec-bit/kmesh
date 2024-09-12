package grpcdata

import (
	"context"
	"encoding/base64"
	"fmt"
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

func handleRequest(req *pb.MsgRequest) ([]byte, error) {
	var err error
	var Msg []byte
	switch req.XdsOpt.XdsNmae {
	case pb.XdsNmae_Cluster:
		valueMsg := &cluster_v2.Cluster{}
		err = proto.Unmarshal(req.Msg, valueMsg)
		if err != nil {
			return nil, err
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
			return nil, err
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
			return nil, fmt.Errorf("unmarshal key failed :%v", err)
		}

		valueMsg := &listener_v2.Listener{}
		err = proto.Unmarshal(req.Msg, valueMsg)
		if err != nil {
			return nil, fmt.Errorf("Unmarshal listener failed:%v", err)
		}
		switch req.XdsOpt.Opt {
		case pb.Opteration_UPDATE:
			err = maps_v2.ListenerUpdate(key, valueMsg)
		case pb.Opteration_LOOKUP:
			err = maps_v2.ListenerLookup(key, valueMsg)
		case pb.Opteration_DELETE:
			err = maps_v2.ListenerDelete(key)
		}
		if err != nil {
			return nil, err
		}
		if valueMsg != nil {
			Msg, err = proto.Marshal(valueMsg)
		}
		if err != nil {
			return nil, fmt.Errorf("marshal listener failed:%v", err)
		}
	case pb.XdsNmae_Route:
		valueMsg := &route_v2.RouteConfiguration{}
		err := proto.Unmarshal(req.Msg, valueMsg)
		if err != nil {
			return nil, err
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
			return nil, err
		}
		Msg, err = proto.Marshal(valueMsg)
	}
	return Msg, err
}

func (s *server) HandleMsg(ctx context.Context, req *pb.MsgRequest) (*pb.MsgResponse, error) {
	log.Debugf("Received req.Name: %v", req.Key)

	Msg, err := handleRequest(req)
	if err != nil {
		return &pb.MsgResponse{ErrorCode: -1, Msg: Msg}, err
	}
	return &pb.MsgResponse{ErrorCode: 0, Msg: Msg}, err
}

func GrpcInitServer() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterKmeshMsgServiceServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
