# DoDAT
This is a tool which builds game files from original source files and a describing DAT file.

It can also verify and fix existing game files against a DAT file.

The tool is able to find source files inside various containers:

- ZIP files
- CD-ROM images (ISO, BIN/CUE, CHD)
- Floppy/hard disk images (IMG, IMA, VHD)

Containers can be nested, for example a CD-ROM image can be inside a ZIP file.

On top of that, the tool is able to reconstruct a CHD file from other types of CD-ROM images if the DAT file contains meta information about the CD-ROM tracks.

## Usage GUI
Run DoDATGUI.exe and use the "..." button to select a DAT file.
If your input source files you want to package are in a different folder than the DAT file you can specify the location in the second row.
And if you want your output files stored in a separate folder, specify the location in the third row.

Next to the "Build Game(s)" button you find a little arrow to switch the mode to either "Verify Game(s)" or "Fix Game(s)".

## Usage Command Line
The command line tool will print the program usage when being run without an argument. At least the `-x` argument needs to be specified. These are the options:

- `-x <PATH>`: Path to input XML file (or - to pass XML via stdin)
- `-s <PATH>`: Path to source file directory (defaults to XML file or current directory)
- `-o <PATH>`: Path to output file directory (defaults to XML file or current directory)
- `-d       `: Use date/time stamps in source instead of XML
- `-p       `: Don't report build failure with only a partial match
- `-v       `: Verify existing files in output file directory
- `-f       `: Fix meta data in existing files that fail verification
- `-q       `: Don't ask for pressing a key at the end

## Download
You can find the download for Windows under the [Releases page](../../releases/latest).  
Just extract it and run DoDATGUI.exe.

For other platforms, see the section below on how to compile the command line tool.

## Compiling
On Windows you can use Visual Studio to compile both GUI and command line tool.

For other platforms, use either `./build-gcc.sh` or `./build-clang.sh` to compile the command line tool for your system.

## License
DoDAT is available under the [GNU General Public License, version 2 or later](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html).
