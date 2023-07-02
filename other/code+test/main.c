#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <errno.h>
#include <elf.h>

#define SAFE_FREE(ptr)   { free(ptr); ptr = NULL;}
#define SAFE_DEL(ptr)    { delete ptr; ptr = NULL;}
#define SAFE_DELARR(ptr) { delete [] ptr; ptr = NULL;}
#define SAFE_FCLOSE(ptr) { fclose(ptr); ptr = NULL;}
#define BUFFER_SIZE 1024

FILE* safe_read_file(char* path);
unsigned int get_file_size(FILE* fp);
unsigned char* get_base_address(FILE* fp, unsigned char* base);
unsigned int get_cmd_line(char* cmd);

void read_elf_header(unsigned char* base);
const char* get_segment_type(Elf32_Word type);
unsigned char* get_shstrtab_name(unsigned char* base, Elf32_Word shstrndx);
void read_prog_table(unsigned char* base);
const char* get_section_type(Elf32_Word type);
void read_sect_table(unsigned char* base);
unsigned char* get_section_flags(Elf32_Word flags);
void read_sect_detail(unsigned char* base);
unsigned char* get_dynstr_name(unsigned char* base, Elf32_Word dynstrndx);
void read_dynsym_table(unsigned char* base);
const char* get_rel_type(Elf32_Word type);
void read_rel_table(unsigned char* base);
const char* get_dynamic_tagname(Elf32_Sword tag);
void read_dyn_section(unsigned char *base);
void read_hex_dump(unsigned char* base, char *num);
void read_bucket_list(unsigned char* base);
void help_document();
void read_rodata_section(unsigned char* base);

int main(int argc, char* argv[])
{
	FILE* fp;
	if (get_cmd_line(argv[1]) == 'x')   // "-x" have four argvs (argc = 4)
	{
		if (argv[3] == NULL)
		{
			printf("!!!input error!!!\n");
			return 0;
		}
		fp = safe_read_file(argv[3]);
	}
	else if (get_cmd_line(argv[1]) == 'H')   // "-H" have two argvs (argc = 2)
	{
		help_document();
		return 0;
	}
	else   // other have three argvs (argc = 3)
	{
    	fp = safe_read_file(argv[2]);
	}
    // such as, FILE* fp = safe_read_file("hello.so");

    unsigned char* base = NULL;   // the base address of ELF
    base = (unsigned char*)malloc(get_file_size(fp));   // allocate memory for ELF
    get_base_address(fp, base);   // get the base address

    /*start to ELF parse*/
    switch (get_cmd_line(argv[1]))
    {
        case 'h':
            read_elf_header(base);
            break;
        case 'l':
            read_prog_table(base);
            break;
        case 'S':
            read_sect_table(base);
            break;
        case 't':
            read_sect_detail(base);
            break;
        case 's': 
            read_dynsym_table(base);
            break;
        case 'r': 
            read_rel_table(base);
            break;
        case 'd': 
            read_dyn_section(base);
            break;
        case 'x':
            read_hex_dump(base, argv[2]);
            break;
        case 'I': 
            read_bucket_list(base);
            break;
		case 'H':
			help_document();
			break;
        default:
			printf("!!!input error!!!\n");
            break;
    }

SAFE_EXIT:
    SAFE_FCLOSE(fp);
    SAFE_FREE(base);

    return 0;
}

/*1.ELF file header*/
void read_elf_header(unsigned char* base)
{
    Elf32_Ehdr* Ehdr = (Elf32_Ehdr*)base;

    printf("ELF Header:\n");

    printf("  Magic: ");
    for (int i = 0; i < EI_NIDENT; ++i) 
	{
        printf("%02x ", Ehdr->e_ident[i]);
    }
    printf("\n");

    printf("  Class:\t\t\t\t");
    switch (Ehdr->e_ident[EI_CLASS]) 
	{
        case ELFCLASSNONE:
            printf("Invalid class\n");
            break;
        case ELFCLASS32:
            printf("ELF32\n");
            break;
        case ELFCLASS64:
            printf("ELF64\n");
            break;
        default:
            printf("Unknown\n");
            break;
    }

    printf("  Data:\t\t\t\t\t");
    switch (Ehdr->e_ident[EI_DATA]) 
	{
        case ELFDATANONE:
            printf("Invalid data encoding\n");
            break;
        case ELFDATA2LSB:
            printf("2's complement, little endian\n");
            break;
        case ELFDATA2MSB:
            printf("2's complement, big endian\n");
            break;
        default:
            printf("Unknown\n");
            break;
    }

    printf("  Version:\t\t\t\t%d (current)\n", Ehdr->e_version);

    printf("  OS/ABI:\t\t\t\t");
    switch (Ehdr->e_ident[EI_OSABI]) 
	{
        case ELFOSABI_SYSV:
            printf("UNIX - System V\n");
            break;
        case ELFOSABI_HPUX:
            printf("HP-UX\n");
            break;
        case ELFOSABI_FREEBSD:
            printf("FreeBSD\n");
            break;
        case ELFOSABI_ARM:
            printf("ARM\n");
            break;
        case ELFOSABI_STANDALONE:
            printf("Standalone (embedded) application\n");
            break;
        default:
            printf("Unknown\n");
            break;
    }

    printf("  ABI Version:\t\t\t\t%d\n", Ehdr->e_ident[EI_ABIVERSION]);

    printf("  Type:\t\t\t\t\t");
    switch (Ehdr->e_type) 
	{
        case ET_NONE:
            printf("No file type\n");
            break;
        case ET_REL:
            printf("Relocatable file\n");
            break;
        case ET_EXEC:
            printf("Executable file\n");
            break;
        case ET_DYN:
            printf("DYN (Shared object file)\n");
            break;
        case ET_CORE:
            printf("Core file\n");
            break;
        default:
            printf("Unknown\n");
            break;
    }

    printf("  Machine:\t\t\t\t");
    switch (Ehdr->e_machine) 
	{
		case EM_386:
			printf("Intel 80386\n");
			break;
        case EM_ARM:
            printf("ARM\n");
            break;
        case EM_X86_64:
            printf("x86-64\n");
            break;
        // Add more machine types as needed
        default:
            printf("Unknown\n");
            break;
    }

    printf("  Version:\t\t\t\t0x%x\n", Ehdr->e_version);
    printf("  Entry point address:\t\t\t0x%08X\n", Ehdr->e_entry);
    printf("  Start of program headers:\t\t%d (bytes into file)\n", Ehdr->e_phoff);
    printf("  Start of section headers:\t\t%d (bytes into file)\n", Ehdr->e_shoff);
    printf("  Flags:\t\t\t\t0x%08X\n", Ehdr->e_flags);
    printf("  Size of this header:\t\t\t%d (bytes)\n", Ehdr->e_ehsize);
    printf("  Size of program headers:\t\t%d (bytes)\n", Ehdr->e_phentsize);
    printf("  Number of program headers:\t\t%d\n", Ehdr->e_phnum);
    printf("  Size of section headers:\t\t%d (bytes)\n", Ehdr->e_shentsize);
    printf("  Number of section headers:\t\t%d\n", Ehdr->e_shnum);
    printf("  Section header string table index: \t%d\n", Ehdr->e_shstrndx);
}

/*program_segment's type*/
const char* get_segment_type(Elf32_Word type) 
{
    switch (type) 
	{
        case 0: return "NULL";
        case 1: return "LOAD";
        case 2: return "DYNAMIC";
        case 3: return "INTERP";
        case 4: return "NOTE";
        case 5: return "SHLIB";
        case 6: return "PHDR";
        default: return "etc.";
    }
}

/*section string table*/
unsigned char* get_shstrtab_name(unsigned char* base, Elf32_Word shstrndx)
{
    Elf32_Ehdr* Ehdr = (Elf32_Ehdr*)base;
    Elf32_Shdr* Shdr = (Elf32_Shdr*)(base + (Ehdr->e_shoff));

    Shdr += Ehdr->e_shstrndx;
    Elf32_Off shstrtab_off = Shdr->sh_offset;
    Elf32_Word shstrtab_size = Shdr->sh_size;

    return base + shstrtab_off + shstrndx;
}

/*2.program headers*/
void read_prog_table(unsigned char* base) 
{
    Elf32_Ehdr* Ehdr = (Elf32_Ehdr*)base;
    Elf32_Phdr* Phdr = (Elf32_Phdr*)(base + (Ehdr->e_phoff));   // ELF pointer base address + offset address
    Elf32_Shdr* Shdr = (Elf32_Shdr*)(base + Ehdr->e_shoff);

    printf("\nElf file type is %s\n", (Ehdr->e_type == ET_DYN) ? "DYN (Shared object file)" : "etc.");
    printf("Entry point 0x%x\n", Ehdr->e_entry);
    printf("There are %d program headers, starting at offset %d\n\n", Ehdr->e_phnum, Ehdr->e_phoff);

    printf("Program Headers:\n");
    printf("  %-15s%-9s%-11s%-11s%-9s%-9s%-4s%-5s\n",
           "Type", "Offset", "VirtAddr", "PhysAddr", "FileSiz", "MemSiz", "Flg", "Align");

    for (int i = 0; i < Ehdr->e_phnum; i++) 
	{
        Elf32_Word p_type = Phdr->p_type;               /* segment type */
        Elf32_Off  p_offset = Phdr->p_offset;           /* segment offset */
        Elf32_Addr p_vaddr = Phdr->p_vaddr;             /* virtual address of segment */
        Elf32_Addr p_paddr = Phdr->p_paddr;             /* physical address - ignored? */
        Elf32_Word p_filesz = Phdr->p_filesz;           /* number of bytes in file for seg. */
        Elf32_Word p_memsz = Phdr->p_memsz;             /* number of bytes in mem. for seg. */
        Elf32_Word p_flags = Phdr->p_flags;             /* flags */
        Elf32_Word p_align = Phdr->p_align;             /* memory alignment */
		
		char flg[4] = "";
		if (p_flags & PF_X) flg[2] = 'E';
		else flg[2]=' ';
		if (p_flags & PF_W) flg[1] = 'W';
		else flg[1]=' ';
		if (p_flags & PF_R) flg[0] = 'R';
		else flg[0]=' ';
		flg[3] = '\0';
        printf("  %-15s0x%06x 0x%08x 0x%08x 0x%06x 0x%06x %s 0x%-2x\n",
               get_segment_type(p_type), p_offset, p_vaddr, p_paddr, p_filesz, p_memsz,
               flg, p_align);

        Phdr++;
    }
    printf("\n");

    Phdr = (Elf32_Phdr*)(base + (Ehdr->e_phoff));
    printf("\nSection to Segment mapping:\n");
    printf("  Segment  Sections...\n");
    for (int i = 0; i < Ehdr->e_phnum; i++) 
	{
        printf("   %02d     ", i);

        Elf32_Word p_offset = Phdr->p_offset;
        Elf32_Word p_filesz = Phdr->p_filesz;

        for (int j = 0; j < Ehdr->e_shnum; j++) 
		{
            Elf32_Word sh_offset = Shdr[j].sh_offset;
            Elf32_Word sh_size = Shdr[j].sh_size;

            if (sh_offset >= p_offset && sh_offset + sh_size <= p_offset + p_filesz) 
			{
                const char* section_name = (char*)get_shstrtab_name(base, Shdr[j].sh_name);
                printf("%s ", section_name);
            }
        }

        printf("\n");
        Phdr++;
    }
}

/*section's type*/
const char* get_section_type(Elf32_Word type) 
{
    switch (type) 
    {
        // Existing section types
        case SHT_NULL:          return "NULL";
        case SHT_PROGBITS:      return "PROGBITS";
        case SHT_SYMTAB:        return "SYMTAB";
        case SHT_STRTAB:        return "STRTAB";
        case SHT_RELA:          return "RELA";
        case SHT_HASH:          return "HASH";
        case SHT_DYNAMIC:       return "DYNAMIC";
        case SHT_NOTE:          return "NOTE";
        case SHT_NOBITS:        return "NOBITS";
        case SHT_REL:           return "REL";
        case SHT_SHLIB:         return "SHLIB";
        case SHT_DYNSYM:        return "DYNSYM";
        case SHT_INIT_ARRAY:    return "INIT_ARRAY";
        case SHT_FINI_ARRAY:    return "FINI_ARRAY";
        case SHT_PREINIT_ARRAY: return "PREINIT_ARRAY";
        case SHT_GROUP:         return "GROUP";
        case SHT_SYMTAB_SHNDX:  return "SYMTAB_SHNDX";
        case SHT_NUM:           return "NUM";
        case SHT_LOOS:          return "LOOS";
        case SHT_HISUNW:        return "HISUNW";
        case SHT_LOPROC:        return "LOPROC";
        case SHT_HIPROC:        return "HIPROC";
        case SHT_LOUSER:        return "LOUSER";
        case SHT_HIUSER:        return "HIUSER";
        
        case 0x6ffffff5:        return "GNU_ATTRIBUTES";
        case 0x6ffffff6:        return "GNU_HASH";
        case 0x6ffffff7:        return "GNU_LIBLIST";
        case 0x6ffffff8:        return "CHECKSUM";
        case 0x6ffffffa:        return "SUNW_COMDAT";
        case 0x6ffffffb:        return "SUNW_syminfo";
        case 0x6ffffffd:        return "GNU_verdef";
        case 0x6ffffffe:        return "GNU_verneed";
        
        default:                return "etc.";
    }
}

/*3.section headers*/
void read_sect_table(unsigned char* base)
{
    Elf32_Ehdr* Ehdr = (Elf32_Ehdr*)base;
    Elf32_Shdr* Shdr = (Elf32_Shdr*)(base + (Ehdr->e_shoff));
	
	printf("There are %d section headers, starting at offset 0x%x:\n", Ehdr->e_shnum, Ehdr->e_shoff);
    printf("\n Section Headers: \n");
	printf("  [Nr] Name\t\t Type\t\t Addr\t  Off\t Size   ES Flg Lk Inf Al\t\n");
    for (int i = 0; i < Ehdr->e_shnum; i++)
    {
        Elf32_Word sh_name = Shdr->sh_name;             /* name - index into section header string table section */
        Elf32_Word sh_type = Shdr->sh_type;             /* type */
        Elf32_Word sh_flags = Shdr->sh_flags;           /* flags */
        Elf32_Addr sh_addr = Shdr->sh_addr;             /* address */
        Elf32_Off  sh_offset = Shdr->sh_offset;         /* file offset */
        Elf32_Word sh_size = Shdr->sh_size;             /* section size */
        Elf32_Word sh_link = Shdr->sh_link;             /* section header table index link */
        Elf32_Word sh_info = Shdr->sh_info;             /* extra information */
        Elf32_Word sh_addralign = Shdr->sh_addralign;   /* address alignment */
        Elf32_Word sh_entsize = Shdr->sh_entsize;       /* section entry size */
			
		printf("  [%02d] %-17.17s %-15.15s %08x %06x %06x %02d %-3d %-2d %-3d %-2d\r\n",
				i, get_shstrtab_name(base, sh_name), get_section_type(sh_type), sh_addr, sh_offset, 
				sh_size, sh_entsize, sh_flags, sh_link, sh_info, sh_addralign);
		Shdr++;
    }
}

/*section's flags*/
unsigned char* get_section_flags(Elf32_Word flags)
{
    static char flags_str[32];
    flags_str[0] = '\0';

    if (flags & SHF_WRITE)
        strcat(flags_str, "WRITE, ");
    if (flags & SHF_ALLOC)
        strcat(flags_str, "ALLOC, ");
    if (flags & SHF_EXECINSTR)
        strcat(flags_str, "EXEC, ");
    if (flags & SHF_MERGE)
        strcat(flags_str, "MERGE, ");
    if (flags & SHF_STRINGS)
        strcat(flags_str, "STRINGS, ");
    if (flags & SHF_INFO_LINK)
        strcat(flags_str, "INFO, ");
    if (flags & SHF_LINK_ORDER)
        strcat(flags_str, "LINK ORDER, ");
    if (flags & SHF_OS_NONCONFORMING)
        strcat(flags_str, "OS NONCONFORMING, ");
    if (flags & SHF_GROUP)
        strcat(flags_str, "GROUP, ");
    if (flags & SHF_TLS)
        strcat(flags_str, "TLS, ");
    if (flags & SHF_MASKOS)
        strcat(flags_str, "MASKOS, ");
    if (flags & SHF_MASKPROC)
        strcat(flags_str, "MASKPROC, ");
    if (flags & SHF_ORDERED)
        strcat(flags_str, "ORDERED, ");
    if (flags & SHF_EXCLUDE)
        strcat(flags_str, "EXCLUDE, ");

    unsigned int len = strlen(flags_str);
    if (len >= 2)
        flags_str[len - 2] = '\0';

    return flags_str;
}

/*4.section details*/
void read_sect_detail(unsigned char* base)
{
    Elf32_Ehdr* Ehdr = (Elf32_Ehdr*)base;
    Elf32_Shdr* Shdr = (Elf32_Shdr*)(base + Ehdr->e_shoff);
	printf("There are %d section headers, starting at offset 0x%x:\n", Ehdr->e_shnum, Ehdr->e_shoff);

    printf("\nSection Headers:\n");
    printf("  [Nr] Name\n");
    printf("       Type            Addr     Off    Size   ES   Lk Inf Al\n");
    printf("       Flags\n");
	
    for (int i = 0; i < Ehdr->e_shnum; i++)
    {
        printf("  [%2d] ", i);
        printf("%-15s\n", get_shstrtab_name(base, Shdr->sh_name));

        printf("       %-15s %08x %06x %06x %02x   %x   %x  %x\n",
           		get_section_type(Shdr->sh_type), Shdr->sh_addr, Shdr->sh_offset,
           		Shdr->sh_size, Shdr->sh_entsize, Shdr->sh_link,
           		Shdr->sh_info, Shdr->sh_addralign);
           
        printf("       [%08X]: %s\n", Shdr->sh_flags, get_section_flags(Shdr->sh_flags));

        Shdr++;
    }
}

/*dynsym string table*/
unsigned char* get_dynstr_name(unsigned char* base, Elf32_Word dynstrndx)
{
    unsigned char* s_data = NULL;
    Elf32_Ehdr* Ehdr = (Elf32_Ehdr*)base;
    Elf32_Shdr* Shdr = (Elf32_Shdr*)(base + (Ehdr->e_shoff));

    for (int i = 0; i < Ehdr->e_shnum; i++)
    {
        if (Shdr->sh_type == SHT_STRTAB)
        {
            s_data = base + Shdr->sh_offset + dynstrndx;
            break;
        }
        Shdr++;
    }
    return s_data;
}

/*5.symbol table*/
void read_dynsym_table(unsigned char* base)
{
    Elf32_Ehdr* Ehdr = (Elf32_Ehdr*)base;
    Elf32_Shdr* Shdr = (Elf32_Shdr*)(base + (Ehdr->e_shoff));

    for (int i = 0; i < Ehdr->e_shnum; i++)
    {
        if (Shdr->sh_type == SHT_DYNSYM)
        {
			printf("\nSymbol table '.dynsym' contains %d entries:\n", (Shdr->sh_size / sizeof(Elf32_Sym)));
			printf("   Num:    Value  Size Type    Bind   Vis       Ndx Name\r\n");	
            Elf32_Sym* Sym = (Elf32_Sym*)(base + (Shdr->sh_offset));
            for (int i = 0; i < (Shdr->sh_size / sizeof(Elf32_Sym)); i++)
            {
                Elf32_Word    st_name = Sym->st_name;       /* name - index into string table */
                Elf32_Addr    st_value = Sym->st_value;     /* symbol value */
                Elf32_Word    st_size = Sym->st_size;       /* symbol size */
                unsigned char st_info = Sym->st_info;       /* type and binding */
                unsigned char st_other = Sym->st_other;     /* 0 - no defined meaning */
                Elf32_Half    st_shndx = Sym->st_shndx;     /* section header index */

				unsigned char bind = ELF32_ST_BIND(st_info);
				unsigned char type = ELF32_ST_TYPE(st_info);
				char* st_bind = NULL;
				char* st_type = NULL;
				switch (bind)
				{
					case 0:
						st_bind = "LOCAL";
						break;
					case 1:
						st_bind = "GLOBAL";
						break;
					case 2:
						st_bind = "WEAK";
						break;
					case 3:
						st_bind = "NUM";
						break;
					case 4:
						st_bind = "LOOS";
						break;
					case 5:
						st_bind = "HIOS";
						break;
					case 6:
						st_bind = "LOPROC";
						break;
					case 7:
						st_bind = "HIPROC";
						break;
					default:
						st_bind = "OTHER";
				}
				switch (type)
				{
					case 0:
						st_type = "NOTYPE";
						break;
					case 1:
						st_type = "OBJECT";
						break;
					case 2:
						st_type = "FUNC";
						break;
					case 3:
						st_type = "SETION";
						break;
					case 4:
						st_type = "FILE";
						break;
					case 5:
						st_type = "NUM";
						break;
					case 6:
						st_type = "GNU_IFUNC";
						break;
					case 7:
						st_type = "LOOS";
						break;
					case 8:
						st_type = "HIOS";
						break;
					case 9:
						st_type = "LOPROC";
						break;
					case 10:
						st_type = "HIPROC";
						break;
					default:
						st_type = "OTHER";
				}
				printf("%6d: %08x  %4d %-7.7s %-6s %-7s %5d %-25.25s\r\n",
						i, st_value, st_size, st_type, st_bind, "DEFAULT", 
						st_shndx, get_dynstr_name(base, st_name));

                Sym++;
            }
            break;
        }
		else if (Shdr->sh_type == SHT_SYMTAB)
		{
			printf("\nSymbol table '.symtab' contains %d entries:\n", (Shdr->sh_size / sizeof(Elf32_Sym)));
			printf("   Num:    Value  Size Type    Bind   Vis       Ndx Name\r\n");
            Elf32_Sym* Sym = (Elf32_Sym*)(base + (Shdr->sh_offset));
            for (int i = 0; i < (Shdr->sh_size / sizeof(Elf32_Sym)); i++)
            {
                Elf32_Word    st_name = Sym->st_name;       /* name - index into string table */
                Elf32_Addr    st_value = Sym->st_value;     /* symbol value */
                Elf32_Word    st_size = Sym->st_size;       /* symbol size */
                unsigned char st_info = Sym->st_info;       /* type and binding */
                unsigned char st_other = Sym->st_other;     /* 0 - no defined meaning */
                Elf32_Half    st_shndx = Sym->st_shndx;     /* section header index */

				unsigned char bind = ELF32_ST_BIND(st_info);
				unsigned char type = ELF32_ST_TYPE(st_info);
				char* st_bind = NULL;
				char* st_type = NULL;
				switch (bind)
				{
					case 0:
						st_bind = "LOCAL";
						break;
					case 1:
						st_bind = "GLOBAL";
						break;
					case 2:
						st_bind = "WEAK";
						break;
					case 3:
						st_bind = "NUM";
						break;
					case 4:
						st_bind = "LOOS";
						break;
					case 5:
						st_bind = "HIOS";
						break;
					case 6:
						st_bind = "LOPROC";
						break;
					case 7:
						st_bind = "HIPROC";
						break;
					default:
						st_bind = "OTHER";
				}
				switch (type)
				{
					case 0:
						st_type = "NOTYPE";
						break;
					case 1:
						st_type = "OBJECT";
						break;
					case 2:
						st_type = "FUNC";
						break;
					case 3:
						st_type = "SETION";
						break;
					case 4:
						st_type = "FILE";
						break;
					case 5:
						st_type = "NUM";
						break;
					case 6:
						st_type = "GNU_IFUNC";
						break;
					case 7:
						st_type = "LOOS";
						break;
					case 8:
						st_type = "HIOS";
						break;
					case 9:
						st_type = "LOPROC";
						break;
					case 10:
						st_type = "HIPROC";
						break;
					default:
						st_type = "OTHER";
				}
				printf("%6d: %08x  %4d %-7.7s %-6s %-7s %5d %-25.25s\r\n",
						i, st_value, st_size, st_type, st_bind, "DEFAULT", 
						st_shndx, get_dynstr_name(base, st_name));

                Sym++;
            }
            break;
        }
        Shdr++;
    }
}

/*rel_type*/
const char* get_rel_type(Elf32_Word type)
{
    switch (type)
    {
        case R_ARM_NONE:
            return "R_ARM_NONE";
        case R_ARM_RELATIVE:
			return "R_ARM_RELATIVE";
		case R_ARM_GLOB_DAT:
			return "R_ARM_GLOB_DAT";
		case R_ARM_JUMP_SLOT:
			return "R_ARM_JUMP_SLOT";
		case R_386_RELATIVE:
			return "R_386_RELATIVE";
		case R_386_GLOB_DAT:
			return "R_386_GLOB_DAT";
		case R_386_JMP_SLOT:
			return "R_386_JMP_SLOT";
		case R_386_PC32:
			return "R_386_PC32";
		case R_386_GOTPC:
			return "R_386_GOTPC";
        default:
            return "etc.";
    }
}

/*6.relocations*/
void read_rel_table(unsigned char* base)
{
    Elf32_Ehdr* Ehdr = (Elf32_Ehdr*)base;
    Elf32_Shdr* Shdr = (Elf32_Shdr*)(base + (Ehdr->e_shoff));
    for (int i = 0; i < Ehdr->e_shnum; i++)
    {
        if (Shdr->sh_type == SHT_REL)
        {
            printf("Relocation section '%s' at offset 0x%x contains %d entries:\r\n",
                    get_shstrtab_name(base, Shdr->sh_name), Shdr->sh_offset, Shdr->sh_size / sizeof(Elf32_Rel));
            printf(" Offset     Info    Type            Sym.Value  Sym. Name\r\n");
 			
            Elf32_Rel* Rel = (Elf32_Rel*)(base + Shdr->sh_offset);

            for (int j = 0; j < Shdr->sh_size / sizeof(Elf32_Rel); j++)
            {
                Elf32_Addr r_offset = Rel->r_offset;    
                Elf32_Word r_info = Rel->r_info;      
                Elf32_Word r_sym = ELF32_R_SYM(r_info);
                Elf32_Word r_type = ELF32_R_TYPE(r_info);

				/* search_dynsym_section */
				Elf32_Shdr* Shdr2 = (Elf32_Shdr*)(base + (Ehdr->e_shoff));
				
				Shdr2 += Shdr->sh_link;   // sh_link is the index of section_header

				Elf32_Sym* Sym2 = (Elf32_Sym*)(base + (Shdr2->sh_offset));
				Sym2 += r_sym;   // r_sym is the index of .dynsym

				Elf32_Addr r_value = Sym2->st_value;
				Elf32_Word r_name = Sym2->st_name;
				const char* name = get_dynstr_name(base, r_name);
				if (name[0] == '\0')
					printf("%08x  %08x %-15s              %-22.22s\r\n", r_offset, r_info, 
							get_rel_type(r_type), get_dynstr_name(base, r_name));
				else 
					printf("%08x  %08x %-15s   %08x   %-22.22s\r\n", r_offset, r_info, 
							get_rel_type(r_type), r_value, get_dynstr_name(base, r_name));

                Rel++;
            }
        }
        Shdr++;
	}
}

/*dynamic_tag_name*/
const char* get_dynamic_tagname(Elf32_Sword tag) 
{
    switch (tag) 
	{
        case DT_NULL:
            return "NULL";
        case DT_NEEDED:
            return "NEEDED";
        case DT_PLTRELSZ:
            return "PLTRELSZ";
        case DT_PLTGOT:
            return "PLTGOT";
        case DT_HASH:
            return "HASH";
        case DT_STRTAB:
            return "STRTAB";
        case DT_SYMTAB:
            return "SYMTAB";
        case DT_RELA:
            return "RELA";
        case DT_RELASZ:
            return "RELASZ";
        case DT_RELAENT:
            return "RELAENT";
        case DT_STRSZ:
            return "STRSZ";
        case DT_SYMENT:
            return "SYMENT";
        case DT_INIT:
            return "INIT";
        case DT_FINI:
            return "FINI";
        case DT_SONAME:
            return "SONAME";
        case DT_RPATH:
            return "RPATH";
        case DT_SYMBOLIC:
            return "SYMBOLIC";
        case DT_REL:
            return "REL";
        case DT_RELSZ:
            return "RELSZ";
        case DT_RELENT:
            return "RELENT";
        case DT_PLTREL:
            return "PLTREL";
        case DT_DEBUG:
            return "DEBUG";
        case DT_TEXTREL:
            return "TEXTREL";
        case DT_JMPREL:
            return "JMPREL";
        case DT_BIND_NOW:
            return "BIND_NOW";
        case DT_INIT_ARRAY:
            return "INIT_ARRAY";
        case DT_FINI_ARRAY:
            return "FINI_ARRAY";
        case DT_INIT_ARRAYSZ:
            return "INIT_ARRAYSZ";
        case DT_FINI_ARRAYSZ:
            return "FINI_ARRAYSZ";
        case DT_NUM:
            return "NUM";
        case DT_LOOS:
            return "LOOS";
        case DT_LOPROC:
            return "LOPROC";
        case DT_HIPROC:
            return "HIPROC";
        case DT_PROCNUM:
            return "PROCNUM";
        case DT_VALRNGLO:
            return "VALRNGLO";
        case DT_POSFLAG_1:
            return "POSFLAG_1";
        case DT_SYMINSZ:
            return "SYMINSZ";
        case DT_SYMINENT:
            return "SYMINENT";
        case DT_ADDRRNGLO:
            return "ADDRRNGLO";
        case DT_SYMINFO:
            return "SYMINFO";
        case DT_VERSYM:
            return "VERSYM";
        case DT_FLAGS_1:
            return "FLAGS_1";
        case DT_VERDEF:
            return "VERDEF";
        case DT_VERDEFNUM:
            return "VERDEFNUM";
        case DT_VERNEED:
            return "VERNEED";
        case DT_VERNEEDNUM:
            return "VERNEEDNUM";
        default:
            return "etc.";
    }
}

/*7.dynamic section*/
void read_dyn_section(unsigned char *base)
{
    Elf32_Ehdr* Ehdr = (Elf32_Ehdr*)base;
    Elf32_Shdr* Shdr = (Elf32_Shdr*)(base + (Ehdr->e_shoff));
    Elf32_Dyn* Dyn = NULL;
    
    for (int i = 0; i < Ehdr->e_shnum; i++)
    {
        if (Shdr->sh_type == SHT_DYNAMIC)
        { 
            Elf32_Dyn* Dyn = (Elf32_Dyn*)(base + (Shdr->sh_offset));
            
            printf("\nDynamic section at offset 0x%x contains %u entries(with null entries):\n",
                    Shdr->sh_offset, Shdr->sh_size / sizeof(Elf32_Dyn));

            printf("  %-12s%-20s %-30s\n", "Tag", "Name", "Name/Value");

            for (int j = 0; j < Shdr->sh_size / sizeof(Elf32_Dyn); j++)
            {
                Elf32_Sword d_tag = Dyn->d_tag;
                Elf32_Addr d_val = Dyn->d_un.d_val;
                const char* tag_name = get_dynamic_tagname(d_tag);
                printf(" 0x%08x  %-21s", d_tag, tag_name);

                if (d_tag == DT_NEEDED || d_tag == DT_SONAME)
                {
                    printf("%s\n", (char*)(base + d_val));
                }
                else
                {
                    printf("0x%x\n", d_val);
                }

                Dyn++;
                if (Dyn->d_tag == 0) 
				{
					printf(" 0x00000000  NULL\t\t  0x0\n");
					break;
				}
            }
        }
        Shdr++;
    }
}

/*8.contents of section*/
void read_hex_dump(unsigned char* base, char *num)
{
	Elf32_Ehdr* Ehdr = (Elf32_Ehdr*)base;
	Elf32_Shdr* Shdr = (Elf32_Shdr*)(base + Ehdr->e_shoff);

	int inum = 0;
	while (*num != '\0')
	{
		inum = inum * 10 + (*num - '0');
		num++;
	}
	Shdr += inum;
	Elf32_Word sh_name = Shdr->sh_name;
	printf("\nHex dump of section '%s':\n", get_shstrtab_name(base, sh_name));

	unsigned char* data = (unsigned char*)(base + Shdr->sh_offset);
	Elf32_Addr addr = Shdr->sh_addr;
	char buffer[BUFFER_SIZE] = "";
	unsigned int idx = 0;
	for (int i = 0; i < Shdr->sh_size; i++)
	{
		if (i % 16 == 0)
		{
			printf("  0x%08x ", addr);
		}
		printf("%02x", *data);
		if ((*data > 0x20) && (*data < 0x7f))
		{
			buffer[idx++] = (char)(*data);
		}
		else
		{
			buffer[idx++] = '.';
		}
		addr++;data++;
		if ((i + 1) % 4 == 0)
		{
			printf(" ");
		}
		if ((i + 1) % 16 == 0)
		{
			buffer[idx] = '\0';
			printf("%s\n", buffer);
			memset(buffer, 0, BUFFER_SIZE);
			idx = 0;
		}
	}
	if (idx != 0)
	{
		int space = 0;
		space = 4 - (idx - 1) / 4 + (16 - idx) * 2;
		if (idx % 4 == 0)
		{
			space--;
		}
		while (space--)
		{
			printf(" ");
		}
		buffer[idx] = '\0';
		printf("%s\n", buffer);
	}
	printf("\n");
}

/*9.histogram of bucket list lengths*/
void read_bucket_list(unsigned char* base)
{
    Elf32_Ehdr* Ehdr = (Elf32_Ehdr*)base;
    Elf32_Shdr* Shdr = (Elf32_Shdr*)(base + Ehdr->e_shoff);

    for (int i = 0; i < Ehdr->e_shnum; i++)
    {
        if (Shdr->sh_type == SHT_HASH)
        {
            Elf32_Word* buckets = (Elf32_Word*)(base + Shdr->sh_offset);
            int numBuckets = buckets[0];
            int symndx = buckets[1];

            printf("Histogram for bucket list length (total of %d buckets):\n", numBuckets);
            printf(" Length  Number     %% of total  Coverage\n");

            int totalCount = 0;
            int* lengthCount = calloc(numBuckets, sizeof(int));

            for (int i = 0; i < numBuckets; i++)
            {
                int length = buckets[i + 2];
                if (length < numBuckets)
                {
                    lengthCount[length]++;
                }
                else
                {
                    lengthCount[numBuckets - 1]++;
                }
                totalCount++;
            }

            for (int i = 0; i < numBuckets; i++)
            {
                float percentTotal = (float)lengthCount[i] / totalCount * 100;
                float coverage = (float)lengthCount[i] / totalCount * 100;
                printf("%7d  %-10d (%6.1f%%)     %6.1f%%\n", i, lengthCount[i], percentTotal, coverage);
            }

            free(lengthCount);
        }
        else if (Shdr->sh_type == SHT_GNU_HASH)
        {
            Elf32_Word* gnuBuckets = (Elf32_Word*)(base + Shdr->sh_offset);
            Elf32_Word numBuckets = gnuBuckets[0];
            Elf32_Word symndx = gnuBuckets[1];
            Elf32_Word maskwords = gnuBuckets[2];
            Elf32_Word shift2 = gnuBuckets[3];

            printf("Histogram for `.gnu.hash' bucket list length (total of %d buckets):\n", numBuckets);
            printf(" Length  Number     %% of total  Coverage\n");

            int totalCount = 0;
            int* lengthCount = calloc(numBuckets, sizeof(int));

            Elf32_Word* hashBloom = gnuBuckets + 4 + maskwords;
            Elf32_Word* hashValues = hashBloom + Shdr->sh_size - (4 + maskwords) * sizeof(Elf32_Word);

            for (int i = 0; i < numBuckets; i++)
            {
                int length = gnuBuckets[i + 4];
                if (length < numBuckets)
                {
                    lengthCount[length]++;
                }
                else
                {
                    lengthCount[numBuckets - 1]++;
                }
                totalCount++;
            }

            for (int i = 0; i < numBuckets; i++)
            {
                float percentTotal = (float)lengthCount[i] / totalCount * 100;
                float coverage = (float)lengthCount[i] / totalCount * 100;
                printf("%7d  %-10d (%6.1f%%)     %6.1f%%\n", i, lengthCount[i], percentTotal, coverage);
            }

            free(lengthCount);
        }
        Shdr++;
    }
}

/*10.help information*/
void help_document()
{
    puts("Usage: ELFTools <option(s)> <file(s)>");
    puts(" Display information about the contents of ELF format files");
    puts(" Options are:");
    puts("  -h Display the ELF file header");
    puts("  -l Display the program headers");
    puts("  -S Display the sections' header");
    puts("  -t Display the section details");
    puts("  -s Display the symbol table");
    puts("  -r Display the relocations (if present)");
    puts("  -d Display the dynamic section (if present)");
    puts("  -x Dump the contents of section <number> as bytes");;
    puts("  -I Display histogram of bucket list lengths");
    puts("  -H Help Document");
}

/*rodata section, but useless*/
void read_rodata_section(unsigned char* base)
{
    unsigned char* s_data = NULL;
    Elf32_Ehdr* Ehdr = (Elf32_Ehdr*)base;
    Elf32_Shdr* Shdr = (Elf32_Shdr*)(base + (Ehdr->e_shoff));

    printf("\n .rodata Section String: \n");
    for (int i = 0; i < Ehdr->e_shnum; i++)
    {
        unsigned char* sh_name = get_shstrtab_name(base, Shdr->sh_name);
        if (strcmp((const char*)sh_name, ".rodata") == 0)
        {
            unsigned char* buff = base + Shdr->sh_offset;
            for (int i = 0; i < Shdr->sh_size; i++)
            {
                if (i == 0)
                    printf("    %s\n", buff);
                if (*buff == '\0')
                    printf("    %s\n", (buff + 1));
                buff++;
            }
            break;
        }
        Shdr++;
    }
}

FILE* safe_read_file(char* path)
{
    FILE * fp = fopen(path, "rb+");
    if (fp == NULL)
    {
        fp = fopen(path, "wb+");
        if (fp == NULL)
        {
            printf("fopen: %d\r\n", errno);
            perror("fopen");
            fp = NULL;
        }
    }
    return fp;
}

unsigned int get_file_size(FILE* fp)
{
    rewind(fp);
    fseek(fp, 0, SEEK_END);
    return ftell(fp);
}

unsigned char* get_base_address(FILE* fp, unsigned char* base)
{
    unsigned long size = get_file_size(fp);
    memset(base, 0, size);
    rewind(fp);
    fread(base, 1, size, fp);
    return base;
}

unsigned int get_cmd_line(char* cmd)
{
    if (!strcmp(cmd, "-h"))
        return 'h';
    if (!strcmp(cmd, "-l"))
        return 'l';
    if (!strcmp(cmd, "-S"))
        return 'S';
    if (!strcmp(cmd, "-t"))
        return 't';
    if (!strcmp(cmd, "-s"))
        return 's';
    if (!strcmp(cmd, "-r"))
        return 'r';
    if (!strcmp(cmd, "-d"))
        return 'd';
    if (!strcmp(cmd, "-x"))
        return 'x';
    if (!strcmp(cmd, "-I"))
        return 'I';
    if (!strcmp(cmd, "-H"))
        return 'H';
    return 0;
}
