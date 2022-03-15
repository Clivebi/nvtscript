if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878116" );
	script_version( "2021-07-14T11:00:55+0000" );
	script_cve_id( "CVE-2020-14019" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-14 11:00:55 +0000 (Wed, 14 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-07 12:15:00 +0000 (Fri, 07 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-07-22 03:19:20 +0000 (Wed, 22 Jul 2020)" );
	script_name( "Fedora: Security Advisory for python-rtslib (FEDORA-2020-46ec9e748b)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2020-46ec9e748b" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/TNMCV2DJJTX345YYBXAMJBXNNVUZQ5UH" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-rtslib'
  package(s) announced via the FEDORA-2020-46ec9e748b advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "API for generic Linux SCSI kernel target. Includes the &#39, target&#39,
service and targetctl tool for restoring configuration." );
	script_tag( name: "affected", value: "'python-rtslib' package(s) on Fedora 32." );
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
	if(!isnull( res = isrpmvuln( pkg: "python-rtslib", rpm: "python-rtslib~2.1.73~1.fc32", rls: "FC32" ) )){
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

