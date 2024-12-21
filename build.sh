# eth2spec's setup.py tries to locate the file tests/core/pyspec/eth2spec/VERSION.txt
# which breaks when running under the pyinstaller packed mode.
# As a workaround, we temporarily create the path it expects.
mkdir eth2spec
touch eth2spec/VERSION.txt

poetry run pyinstaller \
--onefile \
--collect-data eth2spec \
--collect-data dirk_tools ./dirk_tools/main.py \
--name dirk-tools \
--distpath build/dirk-tools

rm -rf eth2spec
