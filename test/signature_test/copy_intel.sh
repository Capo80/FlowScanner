#!/bin/bash

# Source and destination directories
SRC_DIR="/tmp/usr_bin_copy_done"
#SRC_DIR="/home/user/intel_malwares"
#DST_DIR="/home/user/intel64_malwares"

# Check if source directory exists
if [ ! -d "$SRC_DIR" ]; then
  echo "Source directory does not exist: $SRC_DIR"
  exit 1
fi

# Check if destination directory exists, create if not
# if [ ! -d "$DST_DIR" ]; then
#   echo "Destination directory does not exist, creating: $DST_DIR"
#   mkdir -p "$DST_DIR"
# fi

# Loop through all files in the source directory
for file in "$SRC_DIR"/*; do
  # Check if the file is an ELF Intel binary
#   if file "$file" | grep -q 'Intel 80386'; then
#     echo "Copying $file to $DST_DIR"
#     cp "$file" "$DST_DIR"
#   else
    if file "$file" | grep -q 'x86-64'; then
        echo "Copying $file to $DST_DIR (x64)"
        #cp "$file" "$DST_DIR"
    else
        echo "Skipping $file, not an ELF Intel binary"
        rm "$file"
    fi
#   fi
done

echo "Done!"

