if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.121453" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2016-03-14 15:52:46 +0200 (Mon, 14 Mar 2016)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Gentoo Security Advisory GLSA 201603-11" );
	script_tag( name: "insight", value: "Multiple vulnerabilities exist in both Oracles JRE and JDK. Please review the referenced CVEs for additional information." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://security.gentoo.org/glsa/201603-11" );
	script_cve_id( "CVE-2015-0437", "CVE-2015-0458", "CVE-2015-0459", "CVE-2015-0460", "CVE-2015-0469", "CVE-2015-0470", "CVE-2015-0477", "CVE-2015-0478", "CVE-2015-0480", "CVE-2015-0484", "CVE-2015-0486", "CVE-2015-0488", "CVE-2015-0491", "CVE-2015-0492", "CVE-2015-2590", "CVE-2015-2601", "CVE-2015-2613", "CVE-2015-2619", "CVE-2015-2621", "CVE-2015-2625", "CVE-2015-2627", "CVE-2015-2628", "CVE-2015-2632", "CVE-2015-2637", "CVE-2015-2638", "CVE-2015-2659", "CVE-2015-2664", "CVE-2015-4000", "CVE-2015-4729", "CVE-2015-4731", "CVE-2015-4732", "CVE-2015-4733", "CVE-2015-4734", "CVE-2015-4736", "CVE-2015-4748", "CVE-2015-4760", "CVE-2015-4803", "CVE-2015-4805", "CVE-2015-4806", "CVE-2015-4810", "CVE-2015-4835", "CVE-2015-4840", "CVE-2015-4842", "CVE-2015-4843", "CVE-2015-4844", "CVE-2015-4860", "CVE-2015-4868", "CVE-2015-4871", "CVE-2015-4872", "CVE-2015-4881", "CVE-2015-4882", "CVE-2015-4883", "CVE-2015-4893", "CVE-2015-4901", "CVE-2015-4902", "CVE-2015-4903", "CVE-2015-4906", "CVE-2015-4908", "CVE-2015-4911", "CVE-2015-4916", "CVE-2015-7840" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/gentoo", "ssh/login/pkg" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Gentoo Linux Local Security Checks GLSA 201603-11" );
	script_copyright( "Copyright (C) 2016 Eero Volotinen" );
	script_family( "Gentoo Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-gentoo.inc.sc");
res = "";
report = "";
if(( res = ispkgvuln( pkg: "dev-java/oracle-jre-bin", unaffected: make_list( "ge 1.8.0.72 " ), vulnerable: make_list( "lt 1.8.0.72 " ) ) ) != NULL){
	report += res;
}
if(( res = ispkgvuln( pkg: "dev-java/oracle-jdk-bin", unaffected: make_list( "ge 1.8.0.72 " ), vulnerable: make_list( "lt 1.8.0.72 " ) ) ) != NULL){
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

