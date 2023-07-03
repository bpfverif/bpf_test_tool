#!/bin/bash

# Check if the required arguments are provided
if [ $# -ne 1 ]; then
  echo "Usage: $0 <filename>"
  exit 1
fi

bpf_prog_file="$1"
input_file="bpf_test_1.c"
output_file="bpf_test.c"

# Check if the bpf_prog_file exists
if [ ! -f "$bpf_prog_file" ]; then
  echo "File ${bpf_prog_file} does not exist."
  exit 1
fi

# Get the contents of bpf_prog_file and escape special characters
bpf_prog_file_content=$(< "$bpf_prog_file")
bpf_prog_file_content_escaped=$(printf '%s\n' "$bpf_prog_file_content" | sed 's/[\/&*]/\\&/g')

# Search and replace the string in input_file
exp="sed \"s@struct bpf_insn prog\[\] = {};@struct bpf_insn prog[] = {$bpf_prog_file_content_escaped};@\" \"$input_file\" > \"$output_file\""
eval $exp

# compile, and get output
make clean > /dev/null
sudo make bpf_test > /dev/null
echo "-------"
sudo ./bpf_test > bpf_test_output.txt

# Extract the last two lines from bpf_prog_file
last_line=$(tail -n 1 "$bpf_prog_file")
IFS=';' read -ra parts <<< "$last_line" # Set the delimiter to ';' using IFS
last_insn_line_num="${parts[0]/* /}"
branch_to_print_line_num="${parts[1]/ \*\//}"
branch_to_print_line_num=$((branch_to_print_line_num)) # convert to integer
echo "-------"

grep_exp_str="^$last_insn_line_num: ("
grep_exp_str="\"$grep_exp_str\""
grep_exp_branch="^$branch_to_print_line_num: " # only in case of a true branch
if [ "$branch_to_print_line_num" -ge 0 ]; then
  grep_exp="grep ${grep_exp_str} bpf_test_output.txt | tail -n 2; echo "..."; grep -A 1 ${grep_exp_branch} bpf_test_output.txt | tail -n 2"
else
  grep_exp="grep -A 1 ${grep_exp_str}  bpf_test_output.txt | tail -n 2"
fi
eval $grep_exp

echo "-------"
grep "^r[0-9]: " bpf_test_output.txt

