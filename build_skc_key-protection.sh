#!/bin/bash -x
TOP_FOLDER=$PWD/SKC_KEY_PROTECTION_RELEASE_OUTPUT
BUILD_SKC_LiBRARY=$TOP_FOLDER/BUILD
SRC_FOLDER=$PWD
BUILD_LOG_FILE=$TOP_FOLDER/build.log
MANIFEST_FOLDER=$PWD


# Setup folders for build and repo management
function CreateFolders() 
{

    if [ -d "$TOP_FOLDER" ]; then
                echo -n "Removing Top Folder"
                rm -rf $TOP_FOLDER
    fi

    if [ -d "$BUILD_SKC_LiBRARY" ]; then
                echo -n "Removing Build Folder"
                rm -rf $BUILD_SKC_LiBRARY
    fi


        if [ ! -d "$BUILD_SKC_LiBRARY" ]; then
                echo -n "Creating build folder: "
                mkdir -p $BUILD_SKC_LiBRARY 2>&1 > /dev/null
                if [ $? -ne 0 ]; then echo "Failed"; return 1; else echo "Success"; fi
                        rsync -rlptDvz $SRC_FOLDER/ $BUILD_SKC_LiBRARY
        fi

        return 0
}


function BuildKeyAgent() 
{
    echo -ne "${NC}Building Key Agent: "
    cd $BUILD_SKC_LiBRARY && export http_proxy=http://proxy-chain.intel.com:912/ && export https_proxy=http://proxy-chain.intel.com:912/ &&  ./../../scripts/build.sh
    if [ $? -ne 0 ]; then echo "Failed"; return 1; else echo "Completed"; fi
    return 0
}

case "$1" in

--help)
        echo ""
        exit
        ;;
*)
        if [ "$#" -eq  "0" ]
        then
                SRC_DIR=$SRC_FOLDER
        else
                SRC_DIR=$2
        fi

        CreateFolders
        if [ $? -ne 0 ]; then echo; echo "Error, Exit."; exit 1; fi

    BuildKeyAgent
    if [ $? -ne 0 ]; then echo; echo "Build Error, Exit."; exit 1; fi

    ;;

esac

exit 0
