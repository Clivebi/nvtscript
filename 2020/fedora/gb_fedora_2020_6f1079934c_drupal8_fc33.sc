if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878726" );
	script_version( "2021-07-20T11:00:49+0000" );
	script_cve_id( "CVE-2020-28948", "CVE-2020-28949", "CVE-2020-13671", "CVE-2020-13670", "CVE-2020-13669", "CVE-2020-13668", "CVE-2020-13667", "CVE-2020-13666" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-20 11:00:49 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-02 14:36:00 +0000 (Tue, 02 Feb 2021)" );
	script_tag( name: "creation_date", value: "2020-12-15 04:25:32 +0000 (Tue, 15 Dec 2020)" );
	script_name( "Fedora: Security Advisory for drupal8 (FEDORA-2020-6f1079934c)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "FEDORA", value: "2020-6f1079934c" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/KWM4CTMEGAC4I2CHYNJVSROY4CVXVEUT" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'drupal8'
  package(s) announced via the FEDORA-2020-6f1079934c advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Drupal is an open source content management platform powering millions of
websites and applications. Its built, used, and supported by an active and
diverse community of people around the world." );
	script_tag( name: "affected", value: "'drupal8' package(s) on Fedora 33." );
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
	if(!isnull( res = isrpmvuln( pkg: "drupal8", rpm: "drupal8~8.9.11~1.fc33", rls: "FC33" ) )){
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

