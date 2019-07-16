package model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@NoArgsConstructor
@AllArgsConstructor
public class Account {
    private String resourceId;
    private Object _links;
    private String iban;
    private String name;
    private String currency;

}
