if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876379" );
	script_version( "2021-09-01T11:01:35+0000" );
	script_cve_id( "CVE-2017-9470", "CVE-2017-9471", "CVE-2017-9474", "CVE-2017-9058", "CVE-2017-12142", "CVE-2017-12141", "CVE-2017-12144", "CVE-2017-6800", "CVE-2017-6801", "CVE-2017-6802", "CVE-2017-9146", "CVE-2017-6298", "CVE-2017-6299", "CVE-2017-6300", "CVE-2017-6301", "CVE-2017-6302", "CVE-2017-6303", "CVE-2017-6304", "CVE-2017-6305", "CVE-2017-6306", "CVE-2017-9472", "CVE-2017-9473" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 11:01:35 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-05-19 02:09:29 +0000 (Sun, 19 May 2019)" );
	script_name( "Fedora Update for ytnef FEDORA-2019-7d7083b8be" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-7d7083b8be" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LFJWMUEUC4ILH2HEOCYVVLQT654ZMCGQ" );
	script_tag( name: "summary", value: "The remote host is missing an update for the
  'ytnef' package(s) announced via the FEDORA-2019-7d7083b8be advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "insight", value: "Yerase&#39, s TNEF Stream Reader.  Can take a
  TNEF Stream (winmail.dat) sent from Microsoft Outlook (or similar products)
  and extract the attachments, including construction of Contact Cards & Calendar
  entries." );
	script_tag( name: "affected", value: "'ytnef' package(s) on Fedora 30." );
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
	if(!isnull( res = isrpmvuln( pkg: "ytnef", rpm: "ytnef~1.9.3~1.fc30", rls: "FC30" ) )){
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

