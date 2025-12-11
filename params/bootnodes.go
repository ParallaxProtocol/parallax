// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package params

import "github.com/ParallaxProtocol/parallax/common"

// MainnetBootnodes are the enode URLs of the P2P bootstrap nodes running on
// the main Parallax network.
var MainnetBootnodes = []string{
	// Parallax Foundation Go Bootnodes
	// us-boston
	"enode://34957ea19a9c8170892a41633f7ec05c3ca7d13d64fd155c485985c850f8cad72d5fa6ffcba62038580671565b76bd38b61cbc8145a203aa174f1069a3e10eb2@168.231.74.175:32110",
	// eu-frankfurt
	"enode://2060e01e74e46fd944e172373dc18eb1478ec050d9c2d66a4486347c215c5fc5a8f72cb8549419828d61e4f9ff75d31ced7977fc89967546e389ff821a5dc10e@72.61.186.233:32110",
	// br-sao-paulo
	"enode://7fcacf55ab8ffb8bd7bc722ba2336b6a4b304a2fc76fa65aadab4e17d196261793287f2cac80d10a25a351f06a038e73cca1170b2007af076bf82eb33e85d2f3@69.62.94.166:32110",
}

// TestnetBootnodes are the enode URLs of the P2P bootstrap nodes running on the
// test network.
var TestnetBootnodes = []string{}

var V5Bootnodes = []string{
	// Teku team's bootnode
	// "enr:-KG4QOtcP9X1FbIMOe17QNMKqDxCpm14jcX5tiOE4_TyMrFqbmhPZHK_ZPG2Gxb1GE2xdtodOfx9-cgvNtxnRyHEmC0ghGV0aDKQ9aX9QgAAAAD__________4JpZIJ2NIJpcIQDE8KdiXNlY3AyNTZrMaEDhpehBDbZjM_L9ek699Y7vhUJ-eAdMyQW_Fil522Y0fODdGNwgiMog3VkcIIjKA",
	// "enr:-KG4QDyytgmE4f7AnvW-ZaUOIi9i79qX4JwjRAiXBZCU65wOfBu-3Nb5I7b_Rmg3KCOcZM_C3y5pg7EBU5XGrcLTduQEhGV0aDKQ9aX9QgAAAAD__________4JpZIJ2NIJpcIQ2_DUbiXNlY3AyNTZrMaEDKnz_-ps3UUOfHWVYaskI5kWYO_vtYMGYCQRAR3gHDouDdGNwgiMog3VkcIIjKA",
}

// const dnsPrefix = "enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@"

// KnownDNSNetwork returns the address of a public DNS-based node list for the given
// genesis hash and protocol. See https://github.com/ethereum/discv4-dns-lists for more
// information.
func KnownDNSNetwork(genesis common.Hash, protocol string) string {
	return ""
	// var net string
	// switch genesis {
	// case MainnetGenesisHash:
	// 	net = "mainnet"
	// case TestnetGenesisHash:
	// 	net = "testnet"
	// default:
	// 	return ""
	// }
	// return dnsPrefix + protocol + "." + net + ".ethdisco.net"
}
