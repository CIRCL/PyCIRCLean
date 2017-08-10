import sys

from filecheck.filecheck import File


PATH = 'tests/dangerous/bypass.docx'
# PATH = 'tests/normal/word_docx.docx'


def main():
    try:
        file = File(sys.argv[1], '')
    except IndexError:
        file = File(PATH, '')
    file.check()
    print(
        "Name: " + file.filename,
        "Desc: " + file.description_string,
        "Mime: " + file.mimetype,
        "Desc list: " + repr(file._description_string),
        "Size: " + str(file.size),
        "Src path: " + file.src_path,
        "Is dangerous: " + str(file.is_dangerous),
        sep='\n'
    )


if __name__ == '__main__':
    main()
