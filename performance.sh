#!/bin/bash
echo "Enter resolver IP:"
read ip_address

echo "Enter port number:"
read port_number

file="sample_domains.txt"
data_output="${ip_address}_data.csv"
resp_output="${ip_address}_responses.txt"
raw_output="${ip_address}_raw.txt"
error_count=0
query_count=0

# Check if the file exists
if [ ! -f "$file" ]; then
    echo "File not found: $file"
    exit 1
fi

touch "$data_output"
touch "$resp_output"
touch "$raw_output"

# Read the file line by line and process each name
while read line; do
    echo "Querying DNS for $line"
    output=$(python3 client.py ${ip_address} ${port_number} "$line" --timeout 15) # ADD --rd if using public DNS
    query_count=$((query_count + 1))
    echo "$output" >> "$resp_output"
    echo "------------------------" >> "$resp_output"
    # Extract the query time using grep and awk
    query_time=$(echo "$output" | grep -oP 'Query Time: \K\d+')
    if [ -z "$query_time" ]; then
        error_count=$((error_count + 1))
    else
        echo "$line, ${query_time}" >> "$data_output"
        echo "${query_time}" >> "$raw_output"
        fi
done < "$file"

echo "------------------------" >> "$data_output"
echo "Number of queries: $query_count" >> "$data_output"
echo "Number of timeouts/errors: $error_count" >> "$data_output"
result=$(expr $error_count / $query_count)
echo "Error percentage: $result% (approx.)" >> "$data_output"
