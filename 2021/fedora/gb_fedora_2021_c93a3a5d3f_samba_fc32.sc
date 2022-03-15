if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879359" );
	script_version( "2021-08-23T14:00:58+0000" );
	script_cve_id( "CVE-2020-27840", "CVE-2021-20277" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-23 14:00:58 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-26 19:46:00 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2021-04-10 03:04:07 +0000 (Sat, 10 Apr 2021)" );
	script_name( "Fedora: Security Advisory for samba (FEDORA-2021-c93a3a5d3f)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-c93a3a5d3f" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VLZ74IF2N75VQSIHBL4B3P5WKWQCXSRY" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'samba'
  package(s) announced via the FEDORA-2021-c93a3a5d3f advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Samba is the standard Windows interoperability suite of programs for Linux and
Unix." );
	script_tag( name: "affected", value: "'samba' package(s) on Fedora 32." );
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
if(release == "FC32"){
	if(!isnull( res = isrpmvuln( pkg: "samba", rpm: "samba~4.12.14~0.fc32", rls: "FC32" ) )){
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

