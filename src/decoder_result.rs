use libxdc_sys::*;

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DecoderResult {
    Success = decoder_result_s_decoder_success as u32,
    SuccessPtOverflow = decoder_result_s_decoder_success_pt_overflow as u32,
    PageFault = decoder_result_s_decoder_page_fault as u32,
    Error = decoder_result_s_decoder_error as u32,
    UnknownPacket = decoder_result_s_decoder_unkown_packet as u32,
}

impl TryFrom<decoder_result_t> for DecoderResult {
    type Error = String;

    fn try_from(value: decoder_result_t) -> Result<DecoderResult, String> {
        let res = match value as decoder_result_t {
            0 => Ok(DecoderResult::Success),
            1 => Ok(DecoderResult::SuccessPtOverflow),
            2 => Ok(DecoderResult::PageFault),
            3 => Ok(DecoderResult::Error),
            4 => Ok(DecoderResult::UnknownPacket),
            _ => Err(format!("Unknown DecoderResult: {:?}", value))
        };
        if let Ok(val) = res {
            assert_eq!(val as decoder_result_t, value);
        }
        res
    }
}