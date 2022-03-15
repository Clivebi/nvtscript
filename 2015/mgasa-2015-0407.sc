if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.131104" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-10-26 09:36:03 +0200 (Mon, 26 Oct 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Mageia Linux Local Check: mgasa-2015-0407" );
	script_tag( name: "insight", value: "A vulnerability has been found in the nvidia proprietary driver that could be used to allow a local, non-privileged user to corrupt kernel memory. This could be used to gain local root privileges. A local user can issue a specially crafted IOCTL to write a 32-bit integer value stored in the kernel driver to a user-specified memory location, potentially in the kernel address space. The user has a limited ability to influence the value of the integer that is written. (CVE-2015-5950)" );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2015-0407.html" );
	script_cve_id( "CVE-2015-5950" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2015-0407" );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Mageia Linux Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "MAGEIA5"){
	if(( res = isrpmvuln( pkg: "ldetect-lst", rpm: "ldetect-lst~0.1.346.1~1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kmod-nvidia304", rpm: "kmod-nvidia304~304.128~1.mga5.nonfree", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nvidia304", rpm: "nvidia304~304.128~1.mga5.nonfree", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kmod-nvidia340", rpm: "kmod-nvidia340~340.93~1.mga5.nonfree", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nvidia340", rpm: "nvidia340~340.93~1.mga5.nonfree", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kmod-nvidia-current", rpm: "kmod-nvidia-current~346.96~1.mga5.nonfree", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nvidia-current", rpm: "nvidia-current~346.96~1.mga5.nonfree", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

