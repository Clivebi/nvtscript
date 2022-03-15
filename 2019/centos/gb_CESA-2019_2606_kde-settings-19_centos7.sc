if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883109" );
	script_version( "2021-08-27T14:01:18+0000" );
	script_cve_id( "CVE-2019-14744" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-27 14:01:18 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-09-19 02:02:53 +0000 (Thu, 19 Sep 2019)" );
	script_name( "CentOS Update for kde-settings-19 CESA-2019:2606 centos7" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "CESA", value: "2019:2606" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2019-September/023419.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kde-settings-19'
  package(s) announced via the CESA-2019:2606 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The K Desktop Environment (KDE) is a graphical desktop environment for the
X Window System. The kdelibs packages include core libraries for the K
Desktop Environment.

Security Fix(es):

  * kdelibs: malicious desktop files and configuration files lead to code
execution with minimal user interaction (CVE-2019-14744)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * kde.csh profile file contains bourne-shell code (BZ#1740042)" );
	script_tag( name: "affected", value: "'kde-settings-19' package(s) on CentOS 7." );
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
if(release == "CentOS7"){
	if(!isnull( res = isrpmvuln( pkg: "kde-settings", rpm: "kde-settings~19~23.10.el7.centos", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kde-settings-ksplash", rpm: "kde-settings-ksplash~19~23.10.el7.centos", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kde-settings-minimal", rpm: "kde-settings-minimal~19~23.10.el7.centos", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kde-settings-plasma", rpm: "kde-settings-plasma~19~23.10.el7.centos", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kde-settings-pulseaudio", rpm: "kde-settings-pulseaudio~19~23.10.el7.centos", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qt-settings", rpm: "qt-settings~19~23.10.el7.centos", rls: "CentOS7" ) )){
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

