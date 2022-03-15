if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.131296" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2016-05-09 14:18:00 +0300 (Mon, 09 May 2016)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Mageia Linux Local Check: mgasa-2016-0153" );
	script_tag( name: "insight", value: "Updated wireshark packages fix security vulnerabilities: The NCP dissector could crash (CVE-2016-4076). TShark could crash due to a packet reassembly bug (CVE-2016-4077). The IEEE 802.11 dissector could crash (CVE-2016-4078). The PKTC dissector could crash (CVE-2016-4079). The PKTC dissector could crash (CVE-2016-4080). The IAX2 dissector could go into an infinite loop (CVE-2016-4081). Wireshark and TShark could exhaust the stack (CVE-2016-4006). The GSM CBCH dissector could crash (CVE-2016-4082). MS-WSP dissector crash (CVE-2016-4083, CVE-2016-4084)." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2016-0153.html" );
	script_cve_id( "CVE-2016-4076", "CVE-2016-4077", "CVE-2016-4078", "CVE-2016-4079", "CVE-2016-4080", "CVE-2016-4081", "CVE-2016-4006", "CVE-2016-4082", "CVE-2016-4083", "CVE-2016-4084" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2016-0153" );
	script_copyright( "Copyright (C) 2016 Eero Volotinen" );
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
	if(( res = isrpmvuln( pkg: "wireshark", rpm: "wireshark~2.0.3~1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

