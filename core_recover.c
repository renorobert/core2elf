/*

     For original work, refer to ELF EXECUTABLE RECONSTRUCTION FROM A CORE IMAGE
     by Silvio Cesare
 
     http://repo.hackerzvoice.net/depot_ouah/core-reconstruction.txt

*/

#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <elf.h>

static char shstr[] =
        "\0"
        ".symtab\0"
        ".strtab\0"
        ".shstrtab\0"
        ".interp\0"
        ".hash\0"
        ".dynsym\0"
        ".dynstr\0"
        ".rel.got\0"
        ".rel.bss\0"
        ".rel.plt\0"
        ".init\0"
        ".plt\0"
        ".text\0"
        ".fini\0"
        ".rodata\0"
        ".data\0"
        ".ctors\0"
        ".dtors\0"
        ".got\0"
        ".dynamic\0"
        ".bss\0"
        ".comment\0"
        ".note\0"
	".eh_frame_hdr\0"
	".eh_frame\0"
	".init_array\0"
	".fini_array\0"
        ".got.plt\0"
	".rel.dyn\0"
	".gnu.version\0"
	".gnu.version_r\0"
	".gnu.hash\0"
	".tbss\0"
        ".jcr"
;

int sec_index(char *sec_name)
{
    int pos = 0;
    int len = 0;
    
    for (pos = 0; pos < sizeof(shstr);) {
        if(strcmp(sec_name, &shstr[pos]) == 0) {
	    return pos;
	}
	else {
	    len = strlen(&shstr[pos]);
 	    pos += len+1;
	}
    }
    return 0;
}

void die(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

void do_elf_checks(Elf32_Ehdr *ehdr)
{
    if (strncmp(ehdr->e_ident, ELFMAG, SELFMAG)) die("File not ELF");
    if (ehdr->e_type != ET_CORE) die("ELF type not ET_CORE");
    if (ehdr->e_machine != EM_386)
       die("ELF machine type not EM_386");
}

char *xget(int fd, int off, size_t sz)
{
    char *buf;

    if (lseek(fd, off, SEEK_SET) < 0) die("Seek error");
    buf = (char *)malloc(sz);
    if(buf == NULL) die("malloc error");
    if(read(fd, buf, sz) != sz) die("Read error");
    return buf;
}

void cleanup()
{
    unlink("rebuild.elf");
    die("Error writing file: %s", "rebuild.elf");
}

Elf32_Word find_init_size(Elf32_Addr init, Elf32_Addr pltgot, char *data) 
{

    /*
	search for signature

	PLT[0]: push GOT[1]
	        jmp *GOT[2]
	        nops
    */

    typedef struct __attribute__((__packed__)) {
        Elf32_Half push;
	Elf32_Word got1;
        Elf32_Half jump;
	Elf32_Word got2;
	Elf32_Word mnop;
    } Elf32_Plt;

    int i = 0;
    Elf32_Word size = 0;
    Elf32_Plt *plt = (Elf32_Plt *)data;

    for (i = 0; i < 0xf; i++) {
	if (plt[i].got1 == pltgot+4 && plt[i].got2 == pltgot+8) {
	    size = ((init & 0xfffffff0) + 16*i) - init;
	    return size;
	}
    }

    return 0x23;
}

/*
void add_section_hdr(Elf32_Word sh_name, Elf32_Word sh_type,
		     Elf32_Word sh_flags, Elf32_Addr sh_addr,
		     Elf32_Off sh_offset, Elf32_Word sh_size,
		     Elf32_Word sh_link, Elf32_Word sh_info,
		     Elf32_Word sh_addralign, Elf32_Word sh_entsize,
		     int out)
{
    Elf32_Shdr shdr;
    
    shdr.sh_name = sh_name;
    shdr.sh_type = sh_type;
    shdr.sh_addr = sh_addr;
    shdr.sh_offset = sh_offset;
    shdr.sh_size = sh_size;
    shdr.sh_flags = sh_flags;
    shdr.sh_link = sh_link;
    shdr.sh_info = sh_info;
    shdr.sh_addralign = sh_addralign;
    shdr.sh_entsize = sh_entsize;
    
    if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) cleanup();

}
*/


int main(int argc, char **argv)
{
    char *core_file;
    int in, out;
    unsigned int i, p;

    if (argc == 2) core_file = argv[1];
    else core_file = "core";

    /* for core and ELF data */
    Elf32_Ehdr *ehdr, *rec_ehdr;
    Elf32_Phdr *phdr, *rec_phdr, *tmp_phdr;
    Elf32_Shdr shdr;
    Elf32_Dyn *dyn;

    int plen;
    int prog[3];
    int rec_prog[3];
    char *data[3];
    char *rec_data[3];

    /* for section headers */
    Elf32_Addr init	    = 0;
    Elf32_Addr fini	    = 0;
    Elf32_Addr init_array   = 0;
    Elf32_Word init_arraysz = 0;
    Elf32_Addr fini_array   = 0;
    Elf32_Word fini_arraysz = 0;
    Elf32_Addr gnu_hash	    = 0;
    Elf32_Addr strtab	    = 0;
    Elf32_Addr symtab	    = 0;
    Elf32_Word strsz	    = 0;
    Elf32_Word syment 	    = 0;
    Elf32_Addr pltgot       = 0;
    Elf32_Word pltrelsz     = 0;
    Elf32_Addr jmprel       = 0;
    Elf32_Addr rel	    = 0;
    Elf32_Word relsz        = 0;
    Elf32_Word relent       = 0;
    Elf32_Addr verneed	    = 0;
    Elf32_Word verneednum   = 0;
    Elf32_Addr versym	    = 0;
    
    /* for rebulding GOT */
    Elf32_Addr pltaddress   = 0;
    Elf32_Word gotoffset    = 0;

    /* for section header links and info*/
    Elf32_Word dynsym_index = 0;
    Elf32_Word dynstr_index = 0;
    Elf32_Word plt_index    = 0;
    Elf32_Word interp_index = 0;
    Elf32_Word note_index   = 0;
    
    in =  open(core_file, O_RDONLY);
    if (in < 0) die("Coudln't open file: %s", core_file);

    /*
	details of core file
    */

    /* read ELF header */
    ehdr = (Elf32_Ehdr *)malloc(sizeof(Elf32_Ehdr));
    if (ehdr == NULL) die("malloc error");    
    if (read(in, ehdr, sizeof(Elf32_Ehdr)) != sizeof(Elf32_Ehdr)) die("Read error");

    do_elf_checks(ehdr);

    /* read program header */
    if (lseek(in, ehdr->e_phoff, SEEK_SET) < 0) die("Seek error");
    phdr = (Elf32_Phdr *)malloc(plen = sizeof(Elf32_Phdr)*ehdr->e_phnum);
    if (phdr == NULL) die("malloc error");
    if (read(in, phdr, plen) < plen) die("Read error");

    printf("[*] Program headers of CORE\n");
    for(p = 0; p < ehdr->e_phnum; p++) {
	printf("\t0x%08x - 0x%08x\n",
	phdr[p].p_vaddr, phdr[p].p_vaddr+phdr[p].p_memsz);
    }

    /*
	details of ELF
    */

    for (i = 0, p = 0; i < ehdr->e_phnum; i++) {
	if (phdr[i].p_vaddr > 0x08000000 
	&& phdr[i].p_type == PT_LOAD) {
	    prog[p] = i;
	    if (p == 2) break;
	    ++p; 
	}
    }

    for (i = 0; i < 3; i++) {
	data[i] = xget(in, phdr[prog[i]].p_offset, phdr[prog[i]].p_memsz);
    }

    if (phdr[prog[2]].p_memsz > (UINT_MAX - phdr[prog[1]].p_memsz)) die("Integer error");
    data[1] = realloc(data[1], phdr[prog[1]].p_memsz + phdr[prog[2]].p_memsz);
    if(data[1] == NULL) die("malloc error");
    memcpy(data[1]+phdr[prog[1]].p_memsz, data[2], phdr[prog[2]].p_memsz);   
 
    /* ELF header */
    rec_ehdr = (Elf32_Ehdr *)&data[0][0];

    /* program header */
    rec_phdr = (Elf32_Phdr *)&data[0][rec_ehdr->e_phoff];

    printf("\n[*] Program headers of ELF\n");
    for (i = 0; i < rec_ehdr->e_phnum; i++) {
	printf("\t0x%08x - 0x%08x\n",
        rec_phdr[i].p_vaddr, rec_phdr[i].p_vaddr+rec_phdr[i].p_memsz);
    }

    /* fetch PT_LOAD & PT_DYNAMIC */
    for (i = 0, p = 0; i < rec_ehdr->e_phnum; i++) {
	if (rec_phdr[i].p_type == PT_LOAD) {
	    rec_prog[p] = i;
	    if (p == 0) { 
		rec_data[0] = &data[0][0];
	    }
	    else {
		rec_data[1] = &data[1][rec_phdr[i].p_vaddr & 4095];
	    }
	    ++p;
	}
        else if (rec_phdr[i].p_type == PT_DYNAMIC) {
	    rec_prog[2] = i;
	    rec_data[2] = &data[1][rec_phdr[i].p_vaddr & 4095];
	}
    }

    /* section header info */
    rec_ehdr->e_shoff =
                rec_phdr[rec_prog[1]].p_offset +
                rec_phdr[rec_prog[1]].p_filesz +
                sizeof(shstr);

    // fix shnum before closing file
    rec_ehdr->e_shnum = 0;
    rec_ehdr->e_shstrndx = 1;

    // open file for writing ELF
    out = open("rebuild.elf", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IXUSR);
    if (out < 0) die("Failed to open output file");

    for (i = 0; i < 2; i++) {
	Elf32_Phdr *p = &rec_phdr[rec_prog[i]];
	int sz = p->p_filesz;
	if (lseek(out, p->p_offset, SEEK_SET) < 0) cleanup();
	if (write(out, rec_data[i], sz) != sz) cleanup();
    }

    /* write section header names */
    if (write(out, shstr, sizeof(shstr)) != sizeof(shstr)) cleanup();

    /*
	rebuild section headers
    */

    //	NULL 
    memset(&shdr, 0, sizeof(shdr));
    if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) cleanup();
    rec_ehdr->e_shnum++;
   
    /*
        .shstrtab
    */

    shdr.sh_name = sec_index(".shstrtab");
    shdr.sh_type = SHT_STRTAB;
    shdr.sh_addr = 0;
    shdr.sh_offset = rec_ehdr->e_shoff - sizeof(shstr);
    shdr.sh_size = sizeof(shstr);
    shdr.sh_flags = 0;
    shdr.sh_link = 0;
    shdr.sh_info = 0;
    shdr.sh_addralign = 1;
    shdr.sh_entsize = 0;

    if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) cleanup();
    rec_ehdr->e_shnum++;
    
    // rebuild section headers from program header

    printf("\n[*] Building section headers from program headers\n");

    for (i = 0; i < rec_ehdr->e_phnum; i++) {
	switch(rec_phdr[i].p_type) {
	    case PT_INTERP:
		shdr.sh_name = sec_index(".interp");
		shdr.sh_type = SHT_PROGBITS;
		shdr.sh_addr = rec_phdr[i].p_vaddr;
		shdr.sh_offset = rec_phdr[i].p_offset;
		shdr.sh_size = rec_phdr[i].p_filesz;
		shdr.sh_flags = SHF_ALLOC;
    		shdr.sh_link = 0;
    		shdr.sh_info = 0;
    		shdr.sh_addralign = 1;
   		shdr.sh_entsize = 0;
		
		if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) cleanup();
		interp_index = rec_ehdr->e_shnum;
    		rec_ehdr->e_shnum++;
		break;

	    case PT_DYNAMIC:
    		shdr.sh_name = sec_index(".dynamic");
    		shdr.sh_type = SHT_DYNAMIC;
    		shdr.sh_addr = rec_phdr[i].p_vaddr;
    		shdr.sh_offset = rec_phdr[i].p_offset;
    		shdr.sh_size = rec_phdr[i].p_filesz;
    		shdr.sh_flags = SHF_ALLOC;
    		shdr.sh_link = 0;
    		shdr.sh_info = 0;
    		shdr.sh_addralign = 4;
    		shdr.sh_entsize = 8;
    
   		if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) cleanup();
    		rec_ehdr->e_shnum++;
		break;

	    case PT_GNU_EH_FRAME:
		shdr.sh_name = sec_index(".eh_frame_hdr");
		shdr.sh_type = SHT_PROGBITS;
		shdr.sh_addr = rec_phdr[i].p_vaddr;
		shdr.sh_offset = rec_phdr[i].p_offset;
		shdr.sh_size = rec_phdr[i].p_filesz;
		shdr.sh_flags = SHF_ALLOC;
		shdr.sh_link = 0;
		shdr.sh_info = 0;
		shdr.sh_addralign = 4;
		shdr.sh_entsize = 0;
		
		if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) cleanup();
    		rec_ehdr->e_shnum++;

		shdr.sh_name = sec_index(".eh_frame");
		shdr.sh_type = SHT_PROGBITS;
		shdr.sh_addr = rec_phdr[i].p_vaddr + rec_phdr[i].p_filesz;
		shdr.sh_offset = rec_phdr[i].p_offset + rec_phdr[i].p_filesz;
		shdr.sh_size = (rec_phdr[rec_prog[0]].p_vaddr + rec_phdr[rec_prog[0]].p_filesz) -
			       (rec_phdr[i].p_vaddr + rec_phdr[i].p_filesz);
		shdr.sh_flags = SHF_ALLOC;
		shdr.sh_link = 0;
		shdr.sh_info = 0;
		shdr.sh_addralign = 4;
		shdr.sh_entsize = 0;	

		if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) cleanup();
    		rec_ehdr->e_shnum++;
		break;

	    case PT_NOTE:
		shdr.sh_name = sec_index(".note");
		shdr.sh_type = SHT_NOTE;
		shdr.sh_addr = rec_phdr[i].p_vaddr;
		shdr.sh_offset = rec_phdr[i].p_offset;
		shdr.sh_size = rec_phdr[i].p_filesz;
		shdr.sh_flags = SHF_ALLOC;
		shdr.sh_link = 0;
		shdr.sh_info = 0;
		shdr.sh_addralign = 1;
		shdr.sh_entsize = 0;

		if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) cleanup();
		note_index = rec_ehdr->e_shnum;
    		rec_ehdr->e_shnum++;
		break;

	    case PT_TLS:
		shdr.sh_name = sec_index(".tbss");
		shdr.sh_type = SHT_NOBITS;
		shdr.sh_addr = rec_phdr[i].p_vaddr;
		shdr.sh_offset = rec_phdr[i].p_offset;
		shdr.sh_size = rec_phdr[i].p_memsz;
		shdr.sh_flags = SHF_ALLOC | SHF_WRITE | SHF_TLS;
		shdr.sh_link = 0;
		shdr.sh_info = 0;
		shdr.sh_addralign = 4;
		shdr.sh_entsize = 0;
		
                if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) cleanup();
    		rec_ehdr->e_shnum++;
		break;
	    
 	    default:
		break;
	}
    }

    /*
	.bss section
    */

    tmp_phdr = &rec_phdr[rec_prog[1]];

    shdr.sh_name = sec_index(".bss");
    shdr.sh_type = SHT_NOBITS;
    shdr.sh_addr = tmp_phdr->p_vaddr + tmp_phdr->p_filesz;
    shdr.sh_offset = tmp_phdr->p_offset + tmp_phdr->p_filesz;
    shdr.sh_size = tmp_phdr->p_memsz - tmp_phdr->p_filesz;
    shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
    shdr.sh_link = 0;
    shdr.sh_info = 0;
    shdr.sh_addralign = 4;
    shdr.sh_entsize = 0;
    
    if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) cleanup();
    rec_ehdr->e_shnum++;
    
    for (dyn = (Elf32_Dyn *)rec_data[2]; dyn->d_tag != DT_NULL; ++dyn) {
	switch(dyn->d_tag) {
	    case DT_INIT:
		init = dyn->d_un.d_ptr;
		break;

	    case DT_FINI:
		fini = dyn->d_un.d_ptr;
		break;

	    case DT_INIT_ARRAY:
		init_array = dyn->d_un.d_ptr;
		break;

	    case DT_INIT_ARRAYSZ:
		init_arraysz = dyn->d_un.d_val;
		break;

	    case DT_FINI_ARRAY:
		fini_array = dyn->d_un.d_ptr;
		break;

	    case DT_FINI_ARRAYSZ:
		fini_arraysz = dyn->d_un.d_val;
		break;

	    case DT_GNU_HASH:
		gnu_hash = dyn->d_un.d_ptr;
		break;

	    case DT_STRTAB:
		strtab = dyn->d_un.d_ptr;
		break;

	    case DT_SYMTAB:
		symtab = dyn->d_un.d_ptr;
		break;

	    case DT_STRSZ:
		strsz = dyn->d_un.d_val;
		break;

	    case DT_SYMENT:
		syment = dyn->d_un.d_val;
		break;

	    case DT_PLTGOT:
		pltgot = dyn->d_un.d_ptr;
		break;

	    case DT_PLTRELSZ:
		pltrelsz = dyn->d_un.d_val;
		break;

	    case DT_JMPREL:
		jmprel = dyn->d_un.d_ptr;
		break;

	    case DT_REL:
		rel = dyn->d_un.d_ptr;
		break;

	    case DT_RELSZ:
		relsz = dyn->d_un.d_val;
		break;

	    case DT_RELENT:
		relent = dyn->d_un.d_val;
		break;

	    case DT_VERNEED:
		verneed = dyn->d_un.d_ptr;
		break;

	    case DT_VERNEEDNUM:
		verneednum = dyn->d_un.d_val;
		break;

	    case DT_VERSYM:
		versym = dyn->d_un.d_ptr;
		break;

	    default:
		break;
	} 
    }

    printf("[*] Building section headers from DYNAMIC section\n");
    
    /*
	.init_array
    */

    shdr.sh_name = sec_index(".init_array");
    shdr.sh_type = SHT_INIT_ARRAY;
    shdr.sh_addr = init_array;
    shdr.sh_offset = init_array - (rec_phdr[rec_prog[1]].p_vaddr - 
				   rec_phdr[rec_prog[1]].p_offset);
    shdr.sh_size = init_arraysz;
    shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
    shdr.sh_link = 0;
    shdr.sh_info = 0;
    shdr.sh_addralign = 4;
    shdr.sh_entsize = 0;


    if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) cleanup();
    rec_ehdr->e_shnum++;

    /*
	.fini_array
    */

    shdr.sh_name = sec_index(".fini_array");
    shdr.sh_type = SHT_FINI_ARRAY;
    shdr.sh_addr = fini_array;
    shdr.sh_offset = fini_array - (rec_phdr[rec_prog[1]].p_vaddr - 
				   rec_phdr[rec_prog[1]].p_offset);
    shdr.sh_size = fini_arraysz;
    shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
    shdr.sh_link = 0;
    shdr.sh_info = 0;
    shdr.sh_addralign = 4;
    shdr.sh_entsize = 0;

    if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) cleanup();
    rec_ehdr->e_shnum++;

    /*
	.jcr
    */

    shdr.sh_name = sec_index(".jcr");
    shdr.sh_type = SHT_PROGBITS;
    shdr.sh_addr = fini_array + fini_arraysz;
    shdr.sh_offset = shdr.sh_addr - (rec_phdr[rec_prog[1]].p_vaddr - 
				   rec_phdr[rec_prog[1]].p_offset);
    shdr.sh_size = sizeof(Elf32_Addr);
    shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
    shdr.sh_link = 0;
    shdr.sh_info = 0;
    shdr.sh_addralign = 4;
    shdr.sh_entsize = 0;

    if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) cleanup();
    rec_ehdr->e_shnum++;

    /*
	.got.plt
    */

    shdr.sh_name = sec_index(".got.plt");
    shdr.sh_type = SHT_PROGBITS;    
    shdr.sh_addr = pltgot;
    shdr.sh_offset = pltgot - (rec_phdr[rec_prog[1]].p_vaddr - 
			       rec_phdr[rec_prog[1]].p_offset);
    shdr.sh_size = ((pltrelsz/relent) + 3) * sizeof(Elf32_Addr);
    shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
    shdr.sh_link = 0;
    shdr.sh_info = 0;
    shdr.sh_addralign = 4;
    shdr.sh_entsize = 0;

    if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) cleanup();
    rec_ehdr->e_shnum++;

    /*
 	.data - resides after .got.plt
    */

    shdr.sh_name = sec_index(".data");
    shdr.sh_type = SHT_PROGBITS;
    shdr.sh_addr = pltgot + ((pltrelsz/relent) + 3) * sizeof(Elf32_Addr);
    shdr.sh_offset = shdr.sh_addr - (rec_phdr[rec_prog[1]].p_vaddr -
                                     rec_phdr[rec_prog[1]].p_offset);
    shdr.sh_size = (rec_phdr[rec_prog[1]].p_vaddr +  rec_phdr[rec_prog[1]].p_filesz) - 
		   (pltgot + ((pltrelsz/relent) + 3) * sizeof(Elf32_Addr));
    shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
    shdr.sh_link = 0;
    shdr.sh_info = 0;
    shdr.sh_addralign = 4;
    shdr.sh_entsize = 0;
    
    if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) cleanup();
    rec_ehdr->e_shnum++;

    /*
	.dynstr
    */

    shdr.sh_name = sec_index(".dynstr");
    shdr.sh_type = SHT_STRTAB;
    shdr.sh_addr = strtab;
    shdr.sh_offset = strtab - rec_phdr[rec_prog[0]].p_vaddr;
    shdr.sh_size = versym - strtab;
    shdr.sh_flags = SHF_ALLOC;
    shdr.sh_link = 0;
    shdr.sh_info = 0;
    shdr.sh_addralign = 1;
    shdr.sh_entsize = 0;    
    
    if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) cleanup();
    dynstr_index = rec_ehdr->e_shnum;
    rec_ehdr->e_shnum++;

    /*
	.dynsym
    */

    shdr.sh_name = sec_index(".dynsym");
    shdr.sh_type = SHT_DYNSYM;
    shdr.sh_addr = symtab;
    shdr.sh_offset = symtab - rec_phdr[rec_prog[0]].p_vaddr;
    shdr.sh_size = strtab - symtab; 
    shdr.sh_flags = SHF_ALLOC;
    shdr.sh_link = dynstr_index;	        
    shdr.sh_info = interp_index;		
    shdr.sh_addralign = 4;
    shdr.sh_entsize = 16;
    
    if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) cleanup();
    dynsym_index = rec_ehdr->e_shnum;
    rec_ehdr->e_shnum++;

    /*
	.init - resides before plt
    */
 
    shdr.sh_name = sec_index(".init");
    shdr.sh_type = SHT_PROGBITS;
    shdr.sh_addr = init;
    shdr.sh_offset = init - rec_phdr[rec_prog[0]].p_vaddr;
    shdr.sh_size = find_init_size(init, pltgot, &data[0][shdr.sh_offset & 0xfffffff0]);
    shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    shdr.sh_link = 0; 
    shdr.sh_info = 0;
    shdr.sh_addralign = 4;
    shdr.sh_entsize = 0;
    
    if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) cleanup();
    rec_ehdr->e_shnum++;

    /*
        .plt
    */

    shdr.sh_name = sec_index(".plt");
    shdr.sh_type = SHT_PROGBITS;
    shdr.sh_addr = init + 
		   find_init_size(init, pltgot, &data[0][shdr.sh_offset & 0xfffffff0]);
    shdr.sh_offset = shdr.sh_addr - rec_phdr[rec_prog[0]].p_vaddr;
    shdr.sh_size = ((pltrelsz/relent) + 1) * 16;
    shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    shdr.sh_link = 0;
    shdr.sh_info = 0;
    shdr.sh_addralign = 16;
    shdr.sh_entsize = 4;

    if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) cleanup();
    plt_index = rec_ehdr->e_shnum;
    rec_ehdr->e_shnum++;

    pltaddress = shdr.sh_addr;


    /*
        .text section
    */

    tmp_phdr = &rec_phdr[rec_prog[0]];

    shdr.sh_name = sec_index(".text");
    shdr.sh_type = SHT_PROGBITS;
    shdr.sh_addr = pltaddress + ((pltrelsz/relent) + 1) * 16;
    shdr.sh_offset = shdr.sh_addr - tmp_phdr->p_vaddr;
    shdr.sh_size = fini - rec_ehdr->e_entry;
    shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    shdr.sh_link = 0;
    shdr.sh_info = 0;
    shdr.sh_addralign = 16;
    shdr.sh_entsize = 0;

    if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) cleanup();
    rec_ehdr->e_shnum++;

    /*
        .fini
    */

    shdr.sh_name = sec_index(".fini");
    shdr.sh_type = SHT_PROGBITS;
    shdr.sh_addr = fini;
    shdr.sh_offset = fini - rec_phdr[rec_prog[0]].p_vaddr;
    shdr.sh_size = 0; 		// fix this, search for ret ins?
    shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    shdr.sh_link = 0;
    shdr.sh_info = 0;
    shdr.sh_addralign = 4;
    shdr.sh_entsize = 0;

    if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) cleanup();
    rec_ehdr->e_shnum++;

    /*
	.rel.dyn
    */

    shdr.sh_name = sec_index(".rel.dyn");
    shdr.sh_type = SHT_REL;
    shdr.sh_addr = rel;
    shdr.sh_offset = rel - rec_phdr[rec_prog[0]].p_vaddr;
    shdr.sh_size = jmprel - rel;
    shdr.sh_flags = SHF_ALLOC;
    shdr.sh_link = dynsym_index;		
    shdr.sh_info = 0;
    shdr.sh_addralign = 4;
    shdr.sh_entsize = 8;
	
    if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) cleanup();
    rec_ehdr->e_shnum++;

    /*
	.rel.plt
    */

    shdr.sh_name = sec_index(".rel.plt");
    shdr.sh_type = SHT_REL;
    shdr.sh_addr = jmprel;
    shdr.sh_offset = jmprel - rec_phdr[rec_prog[0]].p_vaddr;
    shdr.sh_size = init - jmprel;
    shdr.sh_flags = SHF_ALLOC;
    shdr.sh_link = dynsym_index; 		
    shdr.sh_info = plt_index;		 
    shdr.sh_addralign = 4;
    shdr.sh_entsize = 8;
    
    if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) cleanup();
    rec_ehdr->e_shnum++;


    /*
	.gnu.version
    */
 
    shdr.sh_name = sec_index(".gnu.version");
    shdr.sh_type = SHT_GNU_versym;
    shdr.sh_addr = versym;
    shdr.sh_offset = versym - rec_phdr[rec_prog[0]].p_vaddr;
    shdr.sh_size = ((strtab - symtab)/ sizeof(Elf32_Sym)) * sizeof(Elf32_Half);
    shdr.sh_flags = SHF_ALLOC;
    shdr.sh_link = dynsym_index;
    shdr.sh_info = 0;
    shdr.sh_addralign = 2;
    shdr.sh_entsize = 2;
    
    if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) cleanup();
    rec_ehdr->e_shnum++;

    /*
	.gnu.version_r
    */

    shdr.sh_name = sec_index(".gnu.version_r");
    shdr.sh_type = SHT_GNU_verneed;
    shdr.sh_addr = verneed;
    shdr.sh_offset = verneed - rec_phdr[rec_prog[0]].p_vaddr;
    shdr.sh_size = rel - verneed;
    shdr.sh_flags = SHF_ALLOC;
    shdr.sh_link = dynstr_index;
    shdr.sh_info = verneednum;
    shdr.sh_addralign = 4;
    shdr.sh_entsize = 0;

    if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) cleanup();
    rec_ehdr->e_shnum++;

    /*
	.gnu.hash
    */

    shdr.sh_name = sec_index(".gnu.hash");
    shdr.sh_type = SHT_GNU_HASH;
    shdr.sh_addr = gnu_hash;
    shdr.sh_offset = gnu_hash - rec_phdr[rec_prog[0]].p_vaddr;
    shdr.sh_size = symtab - gnu_hash;
    shdr.sh_flags = SHF_ALLOC;
    shdr.sh_link = dynsym_index;
    shdr.sh_info = 0;
    shdr.sh_addralign = 4;
    shdr.sh_entsize = 0;

    if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) cleanup();
    rec_ehdr->e_shnum++;

    /*
	.got
    */

    shdr.sh_name = sec_index(".got");
    shdr.sh_type = SHT_PROGBITS;
    shdr.sh_addr = rec_phdr[rec_prog[2]].p_vaddr + 
		   rec_phdr[rec_prog[2]].p_filesz;
    shdr.sh_offset = shdr.sh_addr - (rec_phdr[rec_prog[1]].p_vaddr -
                               	     rec_phdr[rec_prog[1]].p_offset);
    shdr.sh_size = pltgot - shdr.sh_addr;
    shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
    shdr.sh_link = 0;
    shdr.sh_info = 0; 
    shdr.sh_addralign = 4;
    shdr.sh_entsize = 4;
    
    if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) cleanup();
    rec_ehdr->e_shnum++;

    
    /*
	rebuild GOT entries
    */
    
    printf("[*] %d GOT entries found\n", (pltrelsz/relent)+3);
    printf("[*] Patching GOT entries to PLT address\n");
   
    gotoffset = rec_phdr[rec_prog[1]].p_offset + 
		(pltgot - rec_phdr[rec_prog[1]].p_vaddr);
    Elf32_Addr plt_entry = NULL;

    /*
    	clear GOT[1] and GOT[2], leaving GOT[0] untouched
    */

    for (i = 1; i < 3; i++) {
        if (lseek(out, gotoffset + sizeof(Elf32_Addr) * i, 
				SEEK_SET) < 0) die("Seek error");
        if (write(out, &plt_entry, sizeof(Elf32_Addr)) 
				!= sizeof(Elf32_Addr)) cleanup();
    }
    
    /*
	overwrite rest of GOT entries with their PLT address
	skip PLT[0]  
    */

    for (i = 3, p = 1; i < (pltrelsz/relent)+3; i++, p++) {
        if (lseek(out, gotoffset + sizeof(Elf32_Addr) * i,
				 SEEK_SET) < 0) die("Seek error");
	plt_entry = pltaddress + (16*p) + 6;	// point to PLT[n]+6
        if (write(out, &plt_entry, sizeof(Elf32_Addr)) 
				 != sizeof(Elf32_Addr)) cleanup();
    }

    /*
	write shnum
    */

    if (lseek(out, sizeof(Elf32_Ehdr) - sizeof(Elf32_Half)*2 , SEEK_SET) < 0) cleanup();
    if (write(out, (char *)&rec_ehdr->e_shnum, sizeof(Elf32_Half)) 
				   != sizeof(Elf32_Half)) cleanup();

    printf("[*] Done\n\n");

    /*
	free resources
    */

    close(in);
    close(out);
    for (i = 0; i < 3; i++) {
        free(data[i]);
    }
    free(ehdr);
    free(phdr);

    return 0;
}
