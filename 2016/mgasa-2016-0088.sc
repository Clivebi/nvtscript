if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.131249" );
	script_version( "2020-06-09T14:44:58+0000" );
	script_tag( name: "creation_date", value: "2016-03-03 14:39:18 +0200 (Thu, 03 Mar 2016)" );
	script_tag( name: "last_modification", value: "2020-06-09 14:44:58 +0000 (Tue, 09 Jun 2020)" );
	script_name( "Mageia Linux Local Check: mgasa-2016-0088" );
	script_tag( name: "insight", value: "Updated xerces-c packages fix security vulnerability: The Xerces-C XML parser mishandles certain kinds of malformed input documents, resulting in buffer overflows during processing and error reporting. The overflows can manifest as a segmentation fault or as memory corruption during a parse operation. The bugs allow for a denial of service attack in many applications by an unauthenticated attacker, and could conceivably result in remote code execution (CVE-2016-0729)." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2016-0088.html" );
	script_cve_id( "CVE-2016-0729" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2016-0088" );
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
	if(( res = isrpmvuln( pkg: "xerces-c", rpm: "xerces-c~3.1.2~1.1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

