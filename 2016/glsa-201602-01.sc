if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.121440" );
	script_version( "2021-09-17T13:01:55+0000" );
	script_tag( name: "creation_date", value: "2016-02-05 14:00:43 +0200 (Fri, 05 Feb 2016)" );
	script_tag( name: "last_modification", value: "2021-09-17 13:01:55 +0000 (Fri, 17 Sep 2021)" );
	script_name( "Gentoo Security Advisory GLSA 201602-01" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been discovered in QEMU. Please review the CVE identifiers referenced below for details." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://security.gentoo.org/glsa/201602-01" );
	script_cve_id( "CVE-2015-1779", "CVE-2015-3456", "CVE-2015-5225", "CVE-2015-5278", "CVE-2015-5279", "CVE-2015-5745", "CVE-2015-6815", "CVE-2015-6855", "CVE-2015-7295", "CVE-2015-7504", "CVE-2015-7512", "CVE-2015-7549", "CVE-2015-8345", "CVE-2015-8504", "CVE-2015-8556", "CVE-2015-8558", "CVE-2015-8567", "CVE-2015-8568", "CVE-2015-8666", "CVE-2015-8701", "CVE-2015-8743", "CVE-2015-8744", "CVE-2015-8745", "CVE-2016-1568" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-03-27 19:15:00 +0000 (Mon, 27 Mar 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Gentoo Linux Local Security Checks GLSA 201602-01" );
	script_copyright( "Copyright (C) 2016 Eero Volotinen" );
	script_family( "Gentoo Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-gentoo.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "app-emulation/qemu", unaffected: make_list( "ge 2.5.0-r1" ), vulnerable: make_list( "lt 2.5.0-r1" ) ) ) != NULL){
	report += res;
}
if( report != "" ){
	security_message( data: report );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}

