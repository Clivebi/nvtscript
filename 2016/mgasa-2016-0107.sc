if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.131266" );
	script_version( "2021-09-20T10:01:48+0000" );
	script_tag( name: "creation_date", value: "2016-03-14 15:57:16 +0200 (Mon, 14 Mar 2016)" );
	script_tag( name: "last_modification", value: "2021-09-20 10:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_name( "Mageia Linux Local Check: mgasa-2016-0107" );
	script_tag( name: "insight", value: "In ISC BIND before 9.10.3-P4, an error parsing input received by the rndc control channel can cause an assertion failure in sexpr.c or alist.c (CVE-2016-1285). In ISC BIND before 9.10.3-P4, a problem parsing resource record signatures for DNAME resource records can lead to an assertion failure in resolver.c or db.c (CVE-2016-1286). In ISC BIND before 9.10.3-P4, A response containing multiple DNS cookies causes servers with cookie support enabled to exit with an assertion failure in resolver.c (CVE-2016-2088)." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2016-0107.html" );
	script_cve_id( "CVE-2016-1285", "CVE-2016-1286", "CVE-2016-2088" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-21 02:29:00 +0000 (Tue, 21 Nov 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2016-0107" );
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
	if(( res = isrpmvuln( pkg: "bind", rpm: "bind~9.10.3.P4~1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

