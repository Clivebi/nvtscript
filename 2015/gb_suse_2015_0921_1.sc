if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851085" );
	script_version( "2020-01-31T07:58:03+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 07:58:03 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-10-16 19:42:41 +0200 (Fri, 16 Oct 2015)" );
	script_cve_id( "CVE-2015-0797" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "SUSE: Security Advisory for gstreamer-0_10-plugins-bad (SUSE-SU-2015:0921-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gstreamer-0_10-plugins-bad'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "gstreamer-0_10-plugins-bad was updated to fix a security issue, a buffer
  overflow in mp4 parsing (bnc#927559 CVE-2015-0797).

  Security Issues:

  * CVE-2015-0797" );
	script_tag( name: "affected", value: "gstreamer-0_10-plugins-bad on SUSE Linux Enterprise Desktop 11 SP3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "SUSE-SU", value: "2015:0921-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=SLED11\\.0SP3" );
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
if(release == "SLED11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-0_10-plugins-bad", rpm: "gstreamer-0_10-plugins-bad~0.10.22~7.11.1", rls: "SLED11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-0_10-plugins-bad-lang", rpm: "gstreamer-0_10-plugins-bad-lang~0.10.22~7.11.1", rls: "SLED11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbasecamerabinsrc-0_10-0", rpm: "libgstbasecamerabinsrc-0_10-0~0.10.22~7.11.1", rls: "SLED11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbasevideo-0_10-0", rpm: "libgstbasevideo-0_10-0~0.10.22~7.11.1", rls: "SLED11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstphotography-0_10-0", rpm: "libgstphotography-0_10-0~0.10.22~7.11.1", rls: "SLED11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstsignalprocessor-0_10-0", rpm: "libgstsignalprocessor-0_10-0~0.10.22~7.11.1", rls: "SLED11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstvdp-0_10-0", rpm: "libgstvdp-0_10-0~0.10.22~7.11.1", rls: "SLED11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbasecamerabinsrc-0_10-0-32bit", rpm: "libgstbasecamerabinsrc-0_10-0-32bit~0.10.22~7.11.1", rls: "SLED11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstbasevideo-0_10-0-32bit", rpm: "libgstbasevideo-0_10-0-32bit~0.10.22~7.11.1", rls: "SLED11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstphotography-0_10-0-32bit", rpm: "libgstphotography-0_10-0-32bit~0.10.22~7.11.1", rls: "SLED11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstsignalprocessor-0_10-0-32bit", rpm: "libgstsignalprocessor-0_10-0-32bit~0.10.22~7.11.1", rls: "SLED11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstvdp-0_10-0-32bit", rpm: "libgstvdp-0_10-0-32bit~0.10.22~7.11.1", rls: "SLED11.0SP3" ) )){
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

