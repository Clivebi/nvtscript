if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.121290" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-09-29 11:28:02 +0300 (Tue, 29 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Gentoo Security Advisory GLSA 201412-04" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been discovered in libvirt. Please review the CVE identifiers referenced below for details." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://security.gentoo.org/glsa/201412-04" );
	script_cve_id( "CVE-2013-4292", "CVE-2013-4296", "CVE-2013-4297", "CVE-2013-4399", "CVE-2013-4400", "CVE-2013-4401", "CVE-2013-5651", "CVE-2013-6436", "CVE-2013-6456", "CVE-2013-6457", "CVE-2013-6458", "CVE-2013-7336", "CVE-2014-0028", "CVE-2014-0179", "CVE-2014-1447", "CVE-2014-3633", "CVE-2014-5177", "CVE-2014-7823" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Gentoo Linux Local Security Checks GLSA 201412-04" );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Gentoo Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-gentoo.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "app-emulation/libvirt", unaffected: make_list( "ge 1.2.9-r2" ), vulnerable: make_list( "lt 1.2.9-r2" ) ) ) != NULL){
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

