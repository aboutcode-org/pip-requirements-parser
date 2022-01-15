
############
# Git-combine SOURCE1 followed by SOURCE2 in new renamed TARGET file
# preserving the detailed history and line-level blame.

# ./ren.sh src/pip/_internal/utils/encoding.py src/pip/_internal/models/index.py src/pip1.py
# ./ren.sh src/pip1.py src/pip/_internal/exceptions.py src/pip2.py
# ./ren.sh src/pip2.py src/pip/_internal/models/format_control.py src/pip3.py
# ./ren.sh src/pip3.py src/pip/_internal/models/search_scope.py src/pip4.py
# ./ren.sh src/pip4.py src/pip/_internal/cli/cmdoptions.py  src/pip5.py
# ./ren.sh src/pip5.py src/pip/_internal/index/package_finder.py  src/pip6.py
# ./ren.sh src/pip6.py src/pip/_internal/req/req_file.py  src/pip7.py
# ./ren.sh src/pip7.py src/pip/_internal/utils/urls.py  src/pip8.py
# ./ren.sh src/pip8.py src/pip/_internal/utils/hashes.py  src/pip9.py
# ./ren.sh src/pip9.py src/pip/_internal/utils/models.py  src/pip10.py
# ./ren.sh src/pip10.py src/pip/_internal/utils/packaging.py  src/pip11.py
# ./ren.sh src/pip11.py src/pip/_internal/models/link.py  src/pip12.py
# ./ren.sh src/pip12.py src/pip/_internal/req/req_install.py  src/pip13.py
# ./ren.sh src/pip13.py src/pip/_internal/vcs/versioncontrol.py  src/pip14.py
# ./ren.sh src/pip14.py src/pip/_internal/utils/misc.py  src/pip15.py
# ./ren.sh src/pip15.py src/pip/_internal/utils/filetypes.py  src/pip16.py
# ./ren.sh src/pip16.py src/pip/_internal/req/constructors.py  src/pip17.py
# ./ren.sh src/pip17.py src/pip/_internal/models/wheel.py  src/pip_requirements.py
#

SOURCE1=$1
SOURCE2=$2
TARGET=$3

# start a new branch
git branch -D renamings
git checkout -b renamings

git mv $SOURCE2 $TARGET
git commit  -m "Rename second python script

Rename $SOURCE2 to $TARGET

Signed-off-by: Philippe Ombredanne <pombredanne@nexb.com>"

git checkout -

git mv $SOURCE1 $TARGET
git commit  -m "Rename first python script

Rename $SOURCE1 to $TARGET

Signed-off-by: Philippe Ombredanne <pombredanne@nexb.com>"

git merge -m "Combine two python files in one

Append $SOURCE2
to $SOURCE1
keeping detailed history.

Signed-off-by: Philippe Ombredanne <pombredanne@nexb.com>" renamings

git cat-file --filters HEAD:$TARGET > $TARGET
git cat-file --filters renamings:$TARGET >> $TARGET
git add $TARGET
git merge --continue

