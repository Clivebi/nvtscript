if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875788" );
	script_version( "2021-09-01T14:01:32+0000" );
	script_cve_id( "CVE-2019-3890" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:01:32 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:49:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-05-07 02:20:48 +0000 (Tue, 07 May 2019)" );
	script_name( "Fedora Update for evolution-ews FEDORA-2019-3a2cc6a0b9" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-3a2cc6a0b9" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/35M7Z22NFLVHDLQT5DV4MHVAHVQMVHU7" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'evolution-ews'
  package(s) announced via the FEDORA-2019-3a2cc6a0b9 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This package allows Evolution to interact with Microsoft Exchange servers,
versions 2007 and later, through its Exchange Web Services (EWS) interface." );
	script_tag( name: "affected", value: "'evolution-ews' package(s) on Fedora 29." );
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
if(release == "FC29"){
	if(!isnull( res = isrpmvuln( pkg: "evolution-ews", rpm: "evolution-ews~3.30.5~2.fc29", rls: "FC29" ) )){
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

