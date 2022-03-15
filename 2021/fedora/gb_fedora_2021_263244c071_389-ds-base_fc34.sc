if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879013" );
	script_version( "2021-08-23T06:00:57+0000" );
	script_cve_id( "CVE-2020-35518" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-23 06:00:57 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-01 14:56:00 +0000 (Thu, 01 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-03-04 04:02:53 +0000 (Thu, 04 Mar 2021)" );
	script_name( "Fedora: Security Advisory for 389-ds-base (FEDORA-2021-263244c071)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-263244c071" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/7FIPUJN3CPORJEGHPQP4ZJFMZ2PPK4LQ" );
	script_tag( name: "summary", value: "The remote host is missing an update for the '389-ds-base'
  package(s) announced via the FEDORA-2021-263244c071 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "389 Directory Server is an LDAPv3 compliant server.  The base package includes
the LDAP server and command line utilities for server administration." );
	script_tag( name: "affected", value: "'389-ds-base' package(s) on Fedora 34." );
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
	if(!isnull( res = isrpmvuln( pkg: "389-ds-base", rpm: "389-ds-base~2.0.3~3.fc34", rls: "FC34" ) )){
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

