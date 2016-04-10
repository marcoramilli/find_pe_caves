#!/usr/bin/env python2

#========================================================================#
#               THIS IS NOT A PRODUCTION RELEASED SOFTWARE               #
#========================================================================#
# Purpose of finMaliciousRelayPoints is to proof the way it's possible to#
# discover TOR malicious Relays Points. Please do not use it in          #

# any production  environment                                            #

# Author: Marco Ramilli                                                  #
# eMail: XXXXXXXX                                                        #
# WebSite: marcoramilli.blogspot.com                                     #
# Use it at your own                                                     #
#========================================================================#

#==============================Disclaimer: ==============================#
#THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR      #
#IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED          #
#WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE  #
#DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,      #
#INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES      #
#(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR      #
#SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)      #
#HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,     #
#STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING   #
#IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE      #
#POSSIBILITY OF SUCH DAMAGE.                                             #
#========================================================================#

#-------------------------------------------------------------------------
#------------------- GENERAL SECTION -------------------------------------
#-------------------------------------------------------------------------
import sys
import re
try:
    import pyprind
except ImportError:
    print 'pyprind not installed, see https://github.com/rasbt/pyprind'
    sys.exit()
try:
    import pefile
    import peutils
except ImportError:
    print 'pefile not installed, see http://code.google.com/p/pefile/'
    sys.exit()
try:
    import magic
except ImportError:
    print 'python-magic is not installed, file types will not be available'
    sys.exit()
import os
import glob

#----------------------------------------------------------------------
#----------------     Starting Coding   -------------------------------
#----------------------------------------------------------------------

def open_file(arg,mode):
    """
    Open a File  and returns the FileNode.
    """
    try:
        file =  open(arg,mode).read()
    except IOError as e:
        print str(e)
        sys.exit(1)
    return file


def get_executables(files):
    """
    Filters the only executable files from a files array
    """
    exec_files = []
    for file in files:
        if "executable" in magic.from_file(file):
            exec_files.append(file)
    return exec_files


def get_sections(binary_file):
    """
    Gets file sections => thanks to PE.
    Returns an multiDimensional array: [binary_file, sections_exe, sections_data]
    """
    sections_exe = []
    sections_data = []
    pe = pefile.PE(data=binary_file)
    sections = pe.sections
    for section in sections:
        # 0x20000000 IMAGE_SCN_MEM_EXECUTE
        # 0x40000000 IMAGE_SCN_MEM_READ
        # 0x00000020 IMAGE_SCN_CNT_CODE
        if all(section.Characteristics & n for n in [0x20000000, 0x40000000, 0x00000020]):
            sections_exe.append(section)
        else:
            sections_data.append(section)
    return [binary_file, sections_exe, sections_data]


def get_codecaves(section,binary,size):
    """
    Looks for caves into a binary file in a specifc PE section
    Return the caves array [section, offsets]
    """
    codecaves = []
    raw_offset = section.PointerToRawData
    length = section.SizeOfRawData
    data = binary[raw_offset:raw_offset + length]
    offsets = [m.start() for m in re.finditer('\x00'*(size), data)]
    if offsets:
        codecaves.append(section)
        codecaves.append(offsets)
    return codecaves


def search_for_codecaves(sections_to_look_for, size):
    """
    Looks for caves in PE sections
    Returns codecaves array
    """
    for section in sections_to_look_for[1]:#exec_sections
        codecaves = get_codecaves(section, sections_to_look_for[0], size)
        if codecaves:
            return codecaves

    for section in sections_to_look_for[2]:
        codecaves = get_codecaves(section, sections_to_look_for[0], size)
        if codecaves:
            return codecaves


def save_files(data):
    """
    Saves a CSV File within stats comma separeted virgula
    Whatchout it creates as many file as analysed files
    """

    for d in data:
        print("[+] Saving plotting file for : %s" % (d[0]))
        fw = open(os.path.basename(d[0]) + ".csv", 'a')
        for point in d[1]:
            fw.write(str(point[0]) + "," + str(point[1]) + "\n")
        fw.close()


if __name__ == "__main__":

    shellcode_minimal_lenght = 21 # http://shell-stormorg/shellcode/files/shellcode-841.php.
    shellcode_max_lenght = 1024
    max_progress = shellcode_max_lenght - shellcode_minimal_lenght
    stats = []

    if len(sys.argv) != 2:
        print "Usage: %s <file|directory>\n" % (sys.argv[0])
        print "The %s will search for caves inside <file|directory> and will save in current directory files within stas" % (sys.argv[0])
        sys.exit()

    object = sys.argv[1]
    files  = []

    if os.path.isdir(object):
        for root, dirs, filenames in os.walk(object):
            for name in filenames:
                files.append(os.path.join(root, name))
    elif os.path.isfile(object):
        files.append(object)
    else:
        print "You must supply a file or directory!"
        sys.exit()

    files = get_executables(files)

    print("")
    print("==========================================")
    print("==========  Doing hard work here =========")
    print("==========================================")
    print("")

    for f in files:
        print ("[+] Calculating carvings for : %s" % (f))
        bar = pyprind.ProgBar(max_progress)
        points = []
        binary_file = open_file(f,"rb")
        sections_to_look_for = get_sections(binary_file) #[binary_file, exe_sections, data_section]

        for size in range(shellcode_minimal_lenght,1025):
            codecaves = search_for_codecaves(sections_to_look_for, size)
            if codecaves:
                codecaves_per_size  = [size, len(codecaves[1])]
            else:
                codecaves_per_size  = [size, 0]
            points.append(codecaves_per_size)
            bar.update()
        stats.append([f, points])

    save_files(stats)







