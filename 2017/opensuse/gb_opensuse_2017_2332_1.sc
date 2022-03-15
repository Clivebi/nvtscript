if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851604" );
	script_version( "2021-09-15T12:01:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 12:01:38 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-03 07:18:44 +0200 (Sun, 03 Sep 2017)" );
	script_cve_id( "CVE-2017-2834", "CVE-2017-2835", "CVE-2017-2836", "CVE-2017-2837", "CVE-2017-2838", "CVE-2017-2839" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-25 15:20:00 +0000 (Fri, 25 May 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for freerdp (openSUSE-SU-2017:2332-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'freerdp'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for freerdp fixes the following issues:

  - CVE-2017-2834: Out-of-bounds write in license_recv() (bsc#1050714)

  - CVE-2017-2835: Out-of-bounds write in rdp_recv_tpkt_pdu (bsc#1050712)

  - CVE-2017-2836: Rdp Client Read Server Proprietary Certificate Denial of
  Service (bsc#1050699)

  - CVE-2017-2837: Client GCC Read Server Security Data DoS (bsc#1050704)

  - CVE-2017-2838: Client License Read Product Info Denial of Service
  Vulnerability (bsc#1050708)

  - CVE-2017-2839: Client License Read Challenge Packet Denial of Service
  (bsc#1050711)

  This update was imported from the SUSE:SLE-12-SP2:Update update project." );
	script_tag( name: "affected", value: "freerdp on openSUSE Leap 42.3, openSUSE Leap 42.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2017:2332-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSELeap42\\.2|openSUSELeap42\\.3)" );
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
if(release == "openSUSELeap42.2"){
	if(!isnull( res = isrpmvuln( pkg: "freerdp", rpm: "freerdp~2.0.0~git.1463131968.4e66df7~3.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freerdp-debuginfo", rpm: "freerdp-debuginfo~2.0.0~git.1463131968.4e66df7~3.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freerdp-debugsource", rpm: "freerdp-debugsource~2.0.0~git.1463131968.4e66df7~3.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freerdp-devel", rpm: "freerdp-devel~2.0.0~git.1463131968.4e66df7~3.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreerdp2", rpm: "libfreerdp2~2.0.0~git.1463131968.4e66df7~3.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreerdp2-debuginfo", rpm: "libfreerdp2-debuginfo~2.0.0~git.1463131968.4e66df7~3.3.1", rls: "openSUSELeap42.2" ) )){
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "freerdp", rpm: "freerdp~2.0.0~git.1463131968.4e66df7~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freerdp-debuginfo", rpm: "freerdp-debuginfo~2.0.0~git.1463131968.4e66df7~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freerdp-debugsource", rpm: "freerdp-debugsource~2.0.0~git.1463131968.4e66df7~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freerdp-devel", rpm: "freerdp-devel~2.0.0~git.1463131968.4e66df7~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreerdp2", rpm: "libfreerdp2~2.0.0~git.1463131968.4e66df7~6.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreerdp2-debuginfo", rpm: "libfreerdp2-debuginfo~2.0.0~git.1463131968.4e66df7~6.1", rls: "openSUSELeap42.3" ) )){
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

