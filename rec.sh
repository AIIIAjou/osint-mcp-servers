#!/bin/bash

mkdir -p recovered_blobs

# 모든 git blob 해시를 순회
git rev-list --all --objects |
while read hash name; do
    # blob 파일인지 체크
    if git cat-file -t $hash 2>/dev/null | grep -q blob; then
        # blob을 복호화해서 저장
        git cat-file -p $hash > recovered_blobs/$hash.txt 2>/dev/null
    fi
done

echo "복구 완료: recovered_blobs 폴더 확인"

