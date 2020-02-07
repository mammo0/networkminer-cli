using System;
using System.ComponentModel;
using System.Globalization;

namespace SharedUtils {
    public class DateTimeAsUtcConverter : System.ComponentModel.DateTimeConverter {
        public override object ConvertTo(ITypeDescriptorContext context, CultureInfo culture, object value, Type destinationType) {
            //return base.ConvertTo(context, culture, value, destinationType);
            if (destinationType == typeof(string) && value is DateTime) {
                DateTime d = (DateTime)value;
                return d.ToUniversalTime().ToString("u");//Displays time in UTC: 2008-04-10 13:30:00Z
            }
            else
                return base.ConvertTo(context, culture, value, destinationType);
        }

    }
}
