// SPDX-License-Identifier: UNLICENSED

pragma solidity >=0.7.0 <0.9.0;

contract Assignment{

    address public teacher;
    address public pupil;
    uint private mark;
    uint public creationTime;
    uint public maxMark;

    constructor(address pupilAddress, uint max) {
        teacher = msg.sender;
        pupil = pupilAddress;
        mark = 0;
        maxMark = max;
        creationTime = block.timestamp;
    }

    function Submit() public {
        uint time = block.timestamp - creationTime;
        require(msg.sender == pupil,
        "Only assigned pupil can submit work.");
        require(time < 864000,
        "Deadline has passed, you may no longer sumbit work.");
        mark = maxMark / 2;
        if(time < 777600){
            mark = 3 * maxMark / 5;
        }
        if(time < 691200){
            mark = 4 * maxMark / 5;
        }
        if(time < 604800){
            mark = maxMark;
        }
    }
}
