package keeper

import (
	"context"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/onsonr/sonr/x/vault/types"
)

var _ types.QueryServer = Querier{}

type Querier struct {
	Keeper
}

func NewQuerier(keeper Keeper) Querier {
	return Querier{Keeper: keeper}
}

func (k Querier) Params(c context.Context, req *types.QueryParamsRequest) (*types.QueryParamsResponse, error) {
	ctx := sdk.UnwrapSDKContext(c)

	p, err := k.Keeper.Params.Get(ctx)
	if err != nil {
		return nil, err
	}

	return &types.QueryParamsResponse{Params: &p}, nil
}

// Sync implements types.QueryServer.
func (k Querier) Sync(goCtx context.Context, req *types.SyncRequest) (*types.SyncResponse, error) {
	// ctx := sdk.UnwrapSDKContext(goCtx)
	return &types.SyncResponse{}, nil
}

// BuildTx implements types.QueryServer.
func (k Querier) BuildTx(goCtx context.Context, req *types.BuildTxRequest) (*types.BuildTxResponse, error) {
	// ctx := sdk.UnwrapSDKContext(goCtx)
	return &types.BuildTxResponse{}, nil
}
