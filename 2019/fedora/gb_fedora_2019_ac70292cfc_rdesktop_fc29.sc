if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875827" );
	script_version( "2021-09-02T08:01:23+0000" );
	script_cve_id( "CVE-2018-8794", "CVE-2018-8795", "CVE-2018-8797", "CVE-2018-20175", "CVE-2018-20176", "CVE-2018-8791", "CVE-2018-8792", "CVE-2018-8793", "CVE-2018-8796", "CVE-2018-8798", "CVE-2018-8799", "CVE-2018-8800", "CVE-2018-20174", "CVE-2018-20177", "CVE-2018-20178", "CVE-2018-20179", "CVE-2018-20180", "CVE-2018-20181", "CVE-2018-20182" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 08:01:23 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-29 01:39:00 +0000 (Tue, 29 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-05-07 02:22:22 +0000 (Tue, 07 May 2019)" );
	script_name( "Fedora Update for rdesktop FEDORA-2019-ac70292cfc" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-ac70292cfc" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/44K6LSAXB2JLUNLQSISCQPFXSKENUAW5" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rdesktop'
  package(s) announced via the FEDORA-2019-ac70292cfc advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "rdesktop is an open source client for Windows NT Terminal Server and
Windows 2000 & 2003 Terminal Services, capable of natively speaking
Remote Desktop Protocol (RDP) in order to present the user&#39, s NT
desktop. Unlike Citrix ICA, no server extensions are required." );
	script_tag( name: "affected", value: "'rdesktop' package(s) on Fedora 29." );
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
	if(!isnull( res = isrpmvuln( pkg: "rdesktop", rpm: "rdesktop~1.8.4~2.fc29", rls: "FC29" ) )){
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

