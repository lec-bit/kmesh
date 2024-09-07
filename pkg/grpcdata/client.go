package grpcdata

import (
	"context"
	"fmt"
	"os"
	"time"

	pb "kmesh.net/kmesh/api/v2/grpcdata"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"kmesh.net/kmesh/pkg/logger"
)

var log = logger.NewLoggerField("workload_controller")

var ConnClient pb.KmeshMsgServiceClient

func SendMsg(c pb.KmeshMsgServiceClient, key string, value []byte, opt *pb.XdsOpt) (error, []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	msgRequest := pb.MsgRequest{
		Key:    key,
		XdsOpt: opt,
		Msg:    value,
	}

	r, err := c.HandleMsg(ctx, &msgRequest)
	if err != nil {
		return err, nil
	}
	if r.ErrorCode != 0 {
		return fmt.Errorf("send failed%v", r.ErrorCode), nil
	}
	return nil, r.Msg
}

func GrpcInitClient() (pb.KmeshMsgServiceClient, *grpc.ClientConn) {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	addr := os.Getenv("KMESHBPFADDR")
	log.Infof("addr :%v", addr)
	conn, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		log.Errorf("grpc failed: %v", err)
		return nil, nil
	}
	c := pb.NewKmeshMsgServiceClient(conn)
	ConnClient = c
	log.Infof("client init success")
	return c, conn
}
