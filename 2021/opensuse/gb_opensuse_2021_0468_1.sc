if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853742" );
	script_version( "2021-08-26T10:01:08+0000" );
	script_cve_id( "CVE-2020-11080" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 10:01:08 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 05:02:30 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for nghttp2 (openSUSE-SU-2021:0468-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0468-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3FQEUDKQEBT4RUZ2JLDQBWSAYUJ4SCTW" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nghttp2'
  package(s) announced via the openSUSE-SU-2021:0468-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for nghttp2 fixes the following issues:

  - CVE-2020-11080: HTTP/2 Large Settings Frame DoS (bsc#1181358)

     This update was imported from the SUSE:SLE-15:Update update project." );
	script_tag( name: "affected", value: "'nghttp2' package(s) on openSUSE Leap 15.2." );
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
if(release == "openSUSELeap15.2"){
	if(!isnull( res = isrpmvuln( pkg: "libnghttp2-14", rpm: "libnghttp2-14~1.40.0~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnghttp2-14-debuginfo", rpm: "libnghttp2-14-debuginfo~1.40.0~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnghttp2-devel", rpm: "libnghttp2-devel~1.40.0~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnghttp2_asio-devel", rpm: "libnghttp2_asio-devel~1.40.0~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnghttp2_asio1", rpm: "libnghttp2_asio1~1.40.0~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnghttp2_asio1-debuginfo", rpm: "libnghttp2_asio1-debuginfo~1.40.0~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nghttp2", rpm: "nghttp2~1.40.0~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nghttp2-debuginfo", rpm: "nghttp2-debuginfo~1.40.0~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nghttp2-debugsource", rpm: "nghttp2-debugsource~1.40.0~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nghttp2-python-debugsource", rpm: "nghttp2-python-debugsource~1.40.0~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-nghttp2", rpm: "python3-nghttp2~1.40.0~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-nghttp2-debuginfo", rpm: "python3-nghttp2-debuginfo~1.40.0~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnghttp2-14-32bit", rpm: "libnghttp2-14-32bit~1.40.0~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnghttp2-14-32bit-debuginfo", rpm: "libnghttp2-14-32bit-debuginfo~1.40.0~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnghttp2_asio1-32bit", rpm: "libnghttp2_asio1-32bit~1.40.0~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libnghttp2_asio1-32bit-debuginfo", rpm: "libnghttp2_asio1-32bit-debuginfo~1.40.0~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
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

