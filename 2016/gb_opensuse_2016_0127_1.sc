if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851155" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2016-01-15 06:15:19 +0100 (Fri, 15 Jan 2016)" );
	script_cve_id( "CVE-2016-0777", "CVE-2016-0778" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:S/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for openssh (openSUSE-SU-2016:0127-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssh'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for openssh fixes the following issues:

  - CVE-2016-0777: A malicious or compromised server could cause the OpenSSH
  client to expose part or all of the client's private key through the
  roaming feature (bsc#961642)

  - CVE-2016-0778: A malicious or compromised server could could trigger a
  buffer overflow in the OpenSSH client through the roaming feature
  (bsc#961645)

  This update disables the undocumented feature supported by the OpenSSH
  client and a commercial SSH server." );
	script_tag( name: "affected", value: "openssh on openSUSE 13.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2016:0127-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE13\\.2" );
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
if(release == "openSUSE13.2"){
	if(!isnull( res = isrpmvuln( pkg: "openssh", rpm: "openssh~6.6p1~5.3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-askpass-gnome", rpm: "openssh-askpass-gnome~6.6p1~5.3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-askpass-gnome-debuginfo", rpm: "openssh-askpass-gnome-debuginfo~6.6p1~5.3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-debuginfo", rpm: "openssh-debuginfo~6.6p1~5.3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-debugsource", rpm: "openssh-debugsource~6.6p1~5.3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-fips", rpm: "openssh-fips~6.6p1~5.3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-helpers", rpm: "openssh-helpers~6.6p1~5.3.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-helpers-debuginfo", rpm: "openssh-helpers-debuginfo~6.6p1~5.3.1", rls: "openSUSE13.2" ) )){
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

