if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850637" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-02-27 05:42:15 +0100 (Fri, 27 Feb 2015)" );
	script_cve_id( "CVE-2012-6303" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for snack (openSUSE-SU-2015:0382-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'snack'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "snack was updated to fix one security issue.

  This security issue was fixed:

  - CVE-2012-6303: Heap-based buffer overflow in the GetWavHeader function
  in generic/jkSoundFile.c in the Snack Sound Toolkit, as used in
  WaveSurfer 1.8.8p4, allowed remote attackers to cause a denial of
  service (crash) and possibly execute arbitrary code via a large chunk
  size in a WAV file (bnc#793860)." );
	script_tag( name: "affected", value: "snack on openSUSE 13.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2015:0382-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE13\\.1" );
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
if(release == "openSUSE13.1"){
	if(!isnull( res = isrpmvuln( pkg: "snack", rpm: "snack~2.2.10~210.4.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "snack-debuginfo", rpm: "snack-debuginfo~2.2.10~210.4.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "snack-debugsource", rpm: "snack-debugsource~2.2.10~210.4.1", rls: "openSUSE13.1" ) )){
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

