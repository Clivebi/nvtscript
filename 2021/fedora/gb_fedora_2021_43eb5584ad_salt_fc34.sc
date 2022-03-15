if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879107" );
	script_version( "2021-08-20T09:01:03+0000" );
	script_cve_id( "CVE-2021-25283", "CVE-2020-28243", "CVE-2020-28972", "CVE-2020-35662", "CVE-2021-3148", "CVE-2021-3144", "CVE-2021-25281", "CVE-2021-25282", "CVE-2021-25284", "CVE-2021-3197" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-20 09:01:03 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-31 14:15:00 +0000 (Wed, 31 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-03-20 04:06:36 +0000 (Sat, 20 Mar 2021)" );
	script_name( "Fedora: Security Advisory for salt (FEDORA-2021-43eb5584ad)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-43eb5584ad" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FUGLOJ6NXLCIFRD2JTXBYQEMAEF2B6XH" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'salt'
  package(s) announced via the FEDORA-2021-43eb5584ad advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Salt is a distributed remote execution system used to execute commands and
query data. It was developed in order to bring the best solutions found in
the world of remote execution together and make them better, faster and more
malleable. Salt accomplishes this via its ability to handle larger loads of
information, and not just dozens, but hundreds or even thousands of individual
servers, handle them quickly and through a simple and manageable interface." );
	script_tag( name: "affected", value: "'salt' package(s) on Fedora 34." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "FC34"){
	if(!isnull( res = isrpmvuln( pkg: "salt", rpm: "salt~3002.5~1.fc34", rls: "FC34" ) )){
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
	exit( 0 );
}
exit( 0 );

