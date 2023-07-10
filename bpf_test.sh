#!/bin/bash

# Check if the required arguments are provided
if [ $# -ne 1 ]; then
  echo "Usage: $0 <ebpf_prog_path>"
  exit 1
fi

script_dir=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd ${script_dir}
bpf_prog_file="$1"
input_file="bpf_test_1.c"
output_file="bpf_test.c"

# Check if the bpf_prog_file exists
if [ ! -f "$bpf_prog_file" ]; then
  echo "File ${bpf_prog_file} does not exist."
  exit 1
fi

exp="sed \"s|bpf_prog.txt|${bpf_prog_file}|g\" ${input_file} > ${output_file}"
eval $exp

# compile, and get output
make clean > /dev/null
sudo make bpf_test > /dev/null
sudo ./bpf_test > bpf_test_output.txt
echo "-----------------------------------------------------"

# Extract the last two lines from bpf_prog_file
last_line=$(tail -n 1 "$bpf_prog_file")
IFS=';' read -ra parts <<< "$last_line" # Set the delimiter to ';' using IFS
last_insn_line_num="${parts[0]/* /}"
jump_outcome="${parts[1]/ \*\//}"
jump_outcome=$((jump_outcome)) # convert to integer

if [ "$jump_outcome" -eq 1 ]; then
  grep_exp_str_1="\"^$last_insn_line_num: (\""
  grep_exp_1="grep ${grep_exp_str_1} bpf_test_output.txt"
  eval $grep_exp_1
  echo "..."
  true_branch_inst_num=$((last_insn_line_num + 3))
  grep_exp_str_2="\"^$true_branch_inst_num: \""
  grep_exp_2="grep -m 1 ${grep_exp_str_2} bpf_test_output.txt"
  eval $grep_exp_2
else
  grep_exp_str="\"^$last_insn_line_num: (\""
  grep_exp="grep -A 1 ${grep_exp_str}  bpf_test_output.txt | tail -n 2"
  eval $grep_exp
fi

echo "-----------------------------------------------------"
grep "^r[0-9]: " bpf_test_output.txt

