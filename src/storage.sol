// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;

contract Storage {

    struct User {
        bytes pubKey;
        bytes32 templateHash;
    }

    User[] public users;

    event Enroll(bytes indexed key, bytes32 indexed hash);

    function store(bytes calldata key, bytes32 hash) public {
        users.push(User({
                pubKey: key,
                templateHash: hash
            }));
        emit Enroll(key, hash);
    }

    function retrieve(bytes calldata key) public view returns (bytes32){
        for (uint i = 0; i < users.length; i++) {
            if (keccak256(abi.encodePacked(users[i].pubKey)) == keccak256(abi.encodePacked(key))){
                return users[i].templateHash;
            }
        }
        return 0;
    }
}