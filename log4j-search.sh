#!/bin/zsh
###############################################################################
# Log4j Vulnerability Audit Extension Attribute
# Created by: Mann Consulting (support@mann.com)
# For support or updates contact support@mann.com
###############################################################################

# Cache file
eaCache="/Library/Application Support/JAMF/eacache/log4jsearch"

# Version where the issue is patched
versionPatched=2.16.0

# Integer, how often we run a full search.
frequency=7

# Set a kill date where we don't run a search any more.  This process is resource intensive and eventually the need for
# this running will deminish.  If the Date is after the kill date we'll just report Expired back to Jamf.
killDate=02/01/2022
killDateDelta=$(((`date -jf %m/%d/%Y "$killDate" +%s` - `date +%s`)/86400))

if [[ $killDateDelta -le 0 ]]; then
  echo "<result>Expired</result>"
  exit
fi

# Make a folder to store our caches.
if [[ ! -d "/Library/Application Support/JAMF/eacache" ]]; then
  mkdir -p "/Library/Application Support/JAMF/eacache"
fi

# Check if the cache file is older than the frequency check and run a full search if it is.
if [[ $(find "$touchFile" -mtime +${frequency} -print 2>/dev/null) ]] || [[ ! -f "$eaCache" ]]; then
  # Search the user data volume ONLY for anything log4j related
  output=$(find /System/Volumes/Data -name "log4j-core*.jar" -mount 2>/dev/null)
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

  if [[ ! -f $i ]];then
    continue
  elif ! unzip -l $i | grep -q JndiLookup.class 2>/dev/null; then
    continue
  elif [[ $versionFound == $versionPass ]];then
    continue
  fi

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
