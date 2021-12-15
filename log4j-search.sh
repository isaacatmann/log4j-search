#!/bin/zsh
###############################################################################
# Log4j Vulnerability Check Extension Attribute
# Created by: Mann Consulting (support@mann.com)
# For support or updates contact support@mann.com
###############################################################################

# Cache file
eaCache="/Library/Application Support/JAMF/eaCache/log4jsearch"

# Version where the issue is patched
versionPatched=2.16.0

# Integer, how often we run a full search.
frequency=7

# Make a folder to store our caches.
if [[ ! -d "/Library/Application Support/JAMF/eacache" ]]; then
  mkdir -p "/Library/Application Support/JAMF/eacache"
fi

# Check if the cache file is older than the frequency check and run a full search if it is.
if [[ $(find "$touchFile" -mtime +${frequency} -print 2>/dev/null) ]] || [[ ! -f "$eaCache" ]]; then
  # Search the user data volume ONLY for anything log4j related
  output=$(find /System/Volumes/Data -name "log4j*.jar" -mount 2>/dev/null)
  echo "$output" > $eaCache
  outputarray=("${(@f)$(cat $eaCache)}")
  echo "$output" > $eaCache
else
  # Cache file is used if it's newer than our frequency.
  outputarray=("${(@f)$(cat $eaCache)}")
fi

# Figure out if the versions on the system are older than our vulnerable version.
for i in $outputarray[@];do
  versionFound=$(basename $i .jar | sed 's/.*-\([0-9\.][0-9\.]*\).*/\1/')
  versionPass=$(printf '%s\n%s\n' "$versionFound" "$versionPatched" | sort -V | tail -n 1)
  if [[ $versionPass == $versionPatched ]]; then
    result+="$i;"
  fi
done

# Output Pass if no vulnerable versions are found, otherwise a semicolon delimited list of vulnerable versions.
if [[ -z $result ]];then
  echo "<result>Pass</result>"
else
  echo "<result>$result</result>"
fi
