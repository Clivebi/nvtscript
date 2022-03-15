if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876483" );
	script_version( "2021-09-01T08:01:24+0000" );
	script_cve_id( "CVE-2019-9740", "CVE-2019-11236" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 08:01:24 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-04 13:15:00 +0000 (Thu, 04 Feb 2021)" );
	script_tag( name: "creation_date", value: "2019-06-13 02:13:11 +0000 (Thu, 13 Jun 2019)" );
	script_name( "Fedora Update for python-urllib3 FEDORA-2019-20bc611b61" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-20bc611b61" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/TBI45HO533KYHNB5YRO43TBYKA3E3VRL" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-urllib3'
  package(s) announced via the FEDORA-2019-20bc611b61 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Python HTTP module with connection pooling and file POST abilities." );
	script_tag( name: "affected", value: "'python-urllib3' package(s) on Fedora 30." );
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
if(release == "FC30"){
	if(!isnull( res = isrpmvuln( pkg: "python-urllib3", rpm: "python-urllib3~1.24.3~1.fc30", rls: "FC30" ) )){
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

