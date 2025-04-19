sudo umount ./tmp/to
sudo rm -rf ./tmp/from
sudo mkdir -p ./tmp/from
sudo sh -c "LD_LIBRARY_PATH=$LIB_PATH ./StackFS_ll -r ./tmp/from ./tmp/to -o allow_other -o max_threads=16 -f"