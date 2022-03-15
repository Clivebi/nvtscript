if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878932" );
	script_version( "2021-08-23T12:01:00+0000" );
	script_cve_id( "CVE-2017-9271" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-23 12:01:00 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-25 17:16:00 +0000 (Thu, 25 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-02-14 04:07:38 +0000 (Sun, 14 Feb 2021)" );
	script_name( "Fedora: Security Advisory for zypper (FEDORA-2021-ebc1c35c5d)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-ebc1c35c5d" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VP2DNHXEQFHXBCTSREPNR7BU4EX64SQG" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'zypper'
  package(s) announced via the FEDORA-2021-ebc1c35c5d advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Zypper is a command line package manager tool using libzypp,
which can be used to manage software for RPM based systems." );
	script_tag( name: "affected", value: "'zypper' package(s) on Fedora 33." );
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
if(release == "FC33"){
	if(!isnull( res = isrpmvuln( pkg: "zypper", rpm: "zypper~1.14.42~1.fc33", rls: "FC33" ) )){
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

