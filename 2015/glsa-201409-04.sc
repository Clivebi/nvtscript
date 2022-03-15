if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.121267" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-09-29 11:27:52 +0300 (Tue, 29 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Gentoo Security Advisory GLSA 201409-04" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been discovered in MySQL. Please review the CVE identifiers referenced below for details." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://security.gentoo.org/glsa/201409-04" );
	script_cve_id( "CVE-2013-1861", "CVE-2013-2134", "CVE-2013-3839", "CVE-2013-5767", "CVE-2013-5770", "CVE-2013-5786", "CVE-2013-5793", "CVE-2013-5807", "CVE-2013-5860", "CVE-2013-5881", "CVE-2013-5882", "CVE-2013-5891", "CVE-2013-5894", "CVE-2013-5908", "CVE-2014-0001", "CVE-2014-0384", "CVE-2014-0386", "CVE-2014-0393", "CVE-2014-0401", "CVE-2014-0402", "CVE-2014-0412", "CVE-2014-0420", "CVE-2014-0427", "CVE-2014-0430", "CVE-2014-0431", "CVE-2014-0433", "CVE-2014-0437", "CVE-2014-2419", "CVE-2014-2430", "CVE-2014-2431", "CVE-2014-2432", "CVE-2014-2434", "CVE-2014-2435", "CVE-2014-2436", "CVE-2014-2438", "CVE-2014-2440" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Gentoo Linux Local Security Checks GLSA 201409-04" );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Gentoo Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-gentoo.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "dev-db/mysql", unaffected: make_list( "ge 5.5.39" ), vulnerable: make_list( "lt 5.5.39" ) ) ) != NULL){
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

