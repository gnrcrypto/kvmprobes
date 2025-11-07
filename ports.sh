#!/bin/bash

for ((port=1; port<=0xffffff; port++)); do
    declare -A results
    null_count=0

    for size in 1 2 4; do
        output=$(kvm_prober readport $port $size 2>/dev/null)
        value=$(echo "$output" | grep -o '0x[0-9A-Fa-f]\+' | tail -1)

        # Filter nulls
        case "$value" in
            "0xFF"|"0xFFFF"|"0xFFFFFFFF")
                ((null_count++))
                results[$size]="(null)"
                ;;
            *)
                # Check if ASCII printable
                intval=$((value))
                if (( intval >= 32 && intval <= 126 )); then
                    char=$(printf "\\x%x" "$intval")
                    results[$size]="$value (ASCII: '$char')"
                else
                    results[$size]="$value"
                fi
                ;;
        esac
    done

    # Only print if at least one size is non-null
    if ((null_count < 3)); then
        echo -n "Port 0x$(printf '%x' $port): "
        for size in 1 2 4; do
            echo -n "size $size → ${results[$size]}  "
        done
        echo
    fi
done
